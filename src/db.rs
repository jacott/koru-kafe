use std::{
    fmt::Display,
    ops::DerefMut,
    sync::{Arc, Mutex, MutexGuard, RwLock},
};

use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use tokio::sync::{RwLock as AsyncRwLock, RwLockReadGuard as AsyncRwLockReadGuard};
use tokio_postgres::{NoTls, Row, ToStatement, types::ToSql};

type ConnectionPool = Pool<PostgresConnectionManager<NoTls>>;
type PgConn = PooledConnection<'static, PostgresConnectionManager<NoTls>>;
type TransStack = Vec<TransState>;

#[derive(Debug)]
pub struct Error {
    reason: String,
}

impl Error {
    pub fn from_pg(err: tokio_postgres::Error) -> Self {
        Self {
            reason: err.to_string(),
        }
    }

    pub fn connect_error<E: Display>(value: E) -> Self {
        Self {
            reason: value.to_string(),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "db::Error {}", self.reason)
    }
}
impl std::error::Error for Error {}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::connect_error(value)
    }
}

#[derive(Clone)]
pub struct Conn {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    conn: AsyncRwLock<Option<PgConn>>,
    trans: Mutex<TransStack>,
    manager: Manager,
}

impl Conn {
    pub fn new(manager: Manager) -> Self {
        Self {
            inner: Arc::new(Inner {
                manager,
                ..Default::default()
            }),
        }
    }

    pub async fn query_opt<T>(&self, statement: &T, params: &[&(dyn ToSql + Sync)]) -> Result<Option<Row>, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.align_trans_state().await?;
        let lock = self.try_get_db_conn().await?;
        let conn = lock.as_ref().expect("should have conn");

        conn.query_opt(statement, params).await.map_err(Error::from_pg)
    }

    pub async fn query<T>(&self, statement: &T, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.align_trans_state().await?;
        let lock = self.try_get_db_conn().await?;
        let conn = lock.as_ref().expect("should have conn");

        conn.query(statement, params).await.map_err(Error::from_pg)
    }

    pub async fn execute<T>(&self, statement: &T, params: &[&(dyn ToSql + Sync)]) -> Result<u64, Error>
    where
        T: ?Sized + ToStatement,
    {
        self.align_trans_state().await?;
        let lock = self.try_get_db_conn().await?;
        let conn = lock.as_ref().expect("should have conn");
        conn.execute(statement, params).await.map_err(Error::from_pg)
    }

    async fn try_get_db_conn(&self) -> Result<AsyncRwLockReadGuard<'_, Option<PgConn>>, Error> {
        {
            let guard = self.inner.conn.read().await;
            if guard.is_some() {
                return Ok(guard);
            }
        }

        let pool = self.inner.manager.pool().await?;
        let mut guard = self.inner.conn.write().await;
        if guard.is_none() {
            let conn = pool.get_owned().await.map_err(Error::connect_error)?;
            *guard = Some(conn);
        }
        drop(guard);
        Ok(self.inner.conn.read().await)
    }

    pub fn begin_transaction(&self) -> Result<Trans, Error> {
        let mut guard = self.lock_trans();
        guard.push(TransState::Pre);
        Ok(Trans(self.clone()))
    }

    pub fn is_in_trans(&self) -> bool {
        let guard = self.lock_trans();
        if guard.is_empty() {
            return false;
        }
        if guard.len() == 1
            && let TransState::Aborting = &guard[0]
        {
            return false;
        }
        true
    }

    fn lock_trans(&self) -> MutexGuard<'_, TransStack> {
        self.inner.trans.lock().expect("should lock")
    }

    fn drop_trans(&self) {
        let mut guard = self.lock_trans();
        let last = guard.len() - 1;
        if let TransState::InProgress = &guard[last] {
            guard.pop();
            guard.push(TransState::Aborting);
            let abort_conn = self.clone();

            tokio::spawn(async move {
                let _ = abort_conn.complete_abort().await;
            });
        } else {
            guard.pop();
        }
    }

    async fn align_trans_state(&self) -> Result<(), Error> {
        if let Some(st) = self.trans_action() {
            if st.is_empty() {
                return self.complete_abort().await;
            }
            let lock = self.try_get_db_conn().await?;
            let conn = lock.as_ref().expect("should have conn");

            conn.batch_execute(&st).await.map_err(Error::from_pg)?;
        }

        Ok(())
    }

    fn trans_action(&self) -> Option<String> {
        let mut guard = self.lock_trans();
        let trans = guard.deref_mut();
        if trans.is_empty() {
            None
        } else {
            let last = trans.len() - 1;
            match &trans[last] {
                TransState::Pre => {
                    let mut begin = String::new();
                    while let Some(s) = trans.pop() {
                        match s {
                            TransState::Pre => {}
                            _ => {
                                trans.push(s);
                                break;
                            }
                        }
                    }
                    while trans.len() <= last {
                        if trans.is_empty() {
                            begin.push_str("BEGIN;");
                        } else {
                            let st = format!("SAVEPOINT s{};", trans.len());
                            begin.push_str(&st);
                        }
                        trans.push(TransState::InProgress);
                    }
                    Some(begin)
                }
                TransState::InProgress | TransState::Committing => None,
                TransState::Aborting => Some("".to_string()),
            }
        }
    }

    async fn complete_abort(&self) -> Result<(), Error> {
        let guard = self.inner.conn.read().await;
        if let Some(conn) = guard.as_deref() {
            let st = {
                let mut guard = self.lock_trans();
                if guard.is_empty() {
                    return Ok(());
                } else {
                    let last = guard.len() - 1;
                    match &guard[last] {
                        TransState::Aborting => {
                            guard.pop();
                            if last == 0 { "ROLLBACK".to_string() } else { format!("ROLLBACK TO SAVEPOINT s{}", last) }
                        }
                        _ => return Ok(()),
                    }
                }
            };
            conn.execute(&st, &[]).await.map_err(Error::from_pg)?;
        }

        Ok(())
    }

    async fn commit(&self) -> Result<(), Error> {
        let guard = self.inner.conn.read().await;
        match guard.as_deref() {
            Some(conn) => {
                let st = {
                    let mut guard = self.lock_trans();
                    let last = guard.len() - 1;
                    match &guard[last] {
                        TransState::InProgress => {
                            guard.pop();
                            guard.push(TransState::Committing);
                        }
                        _ => return Err("Not in transaction".into()),
                    }
                    if last == 0 { "COMMIT".to_string() } else { format!("RELEASE s{}", last) }
                };
                conn.execute(&st, &[]).await.map_err(Error::from_pg)?;
                Ok(())
            }

            None => Err("no connection in progress".into()),
        }
    }
}

pub struct Trans(Conn);

impl Trans {
    pub async fn commit(self) -> Result<(), Error> {
        self.0.commit().await
    }

    pub fn clone_conn(&self) -> Conn {
        self.0.clone()
    }
}

impl Drop for Trans {
    fn drop(&mut self) {
        self.0.drop_trans()
    }
}

#[derive(Default)]
enum TransState {
    #[default]
    Pre,
    InProgress,
    Aborting,
    Committing,
}

#[derive(Default, Clone)]
pub struct Manager {
    inner: Arc<ManagerInner>,
}
impl Manager {
    async fn pool(&self) -> Result<ConnectionPool, Error> {
        {
            let guard = self.inner.pool.read().await;
            if let Some(pool) = guard.as_ref() {
                return Ok(pool.clone());
            }
        }
        let mut guard = self.inner.pool.write().await;
        match guard.as_ref() {
            Some(pool) => Ok(pool.clone()),
            None => {
                let pool = new_pool(&self.url()).await.map_err(Error::connect_error)?;
                *guard = Some(pool.clone());
                Ok(pool)
            }
        }
    }

    pub fn set_url(&self, url: &str) -> Result<(), Error> {
        let mut guard = self.inner.url.write().expect("should lock");
        if guard.is_empty() {
            *guard += url;
            Ok(())
        } else {
            Err("url already set".into())
        }
    }

    pub fn url(&self) -> String {
        let guard = self.inner.url.read().expect("should lock");
        guard.clone()
    }
}

#[derive(Default)]
pub struct ManagerInner {
    url: RwLock<String>,
    pool: AsyncRwLock<Option<ConnectionPool>>,
}

async fn new_pool(conn_str: &str) -> Result<ConnectionPool, tokio_postgres::Error> {
    let manager = PostgresConnectionManager::new_from_stringlike(conn_str, NoTls)?;

    Pool::builder().build(manager).await
}

impl From<Error> for crate::ts_net::Error {
    fn from(value: Error) -> Self {
        Self::internal_error(value.to_string())
    }
}

#[cfg(test)]
#[path = "db_test.rs"]
mod test;
