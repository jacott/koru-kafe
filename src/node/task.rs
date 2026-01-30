use std::sync::{Arc, RwLock};

use tokio::task::futures::TaskLocalFuture;

use crate::db;

use super::{KoruNode, remote_cursors};

tokio::task_local! {
    static KORU_TASK: Task;
}

struct Inner {
    conn: db::Conn,
    global: Global,
}

#[derive(Clone)]
pub struct Task {
    inner: Arc<Inner>,
}
impl Default for Task {
    fn default() -> Self {
        let global = Global::default();
        let manager = global.inner.db.clone();
        Self {
            inner: Arc::new(Inner {
                global,
                conn: db::Conn::new(manager),
            }),
        }
    }
}
impl Task {
    #[cfg(test)]
    pub fn new_with_same_tran() -> Self {
        let global = Global {
            inner: Arc::new(GlobalInner {
                same_tran: true,
                ..Default::default()
            }),
        };
        let manager = global.inner.db.clone();
        Self {
            inner: Arc::new(Inner {
                global,
                conn: db::Conn::new(manager),
            }),
        }
    }

    pub fn scope<F: Future>(f: F) -> TaskLocalFuture<Self, F> {
        let global = Self::global();
        let manager = global.inner.db.clone();

        #[cfg(test)]
        let conn = if global.inner.same_tran { Self::db_conn() } else { db::Conn::new(manager) };

        #[cfg(not(test))]
        let conn = db::Conn::new(manager);

        let task = Self {
            inner: Arc::new(Inner { global, conn }),
        };
        KORU_TASK.scope(task, f)
    }

    pub fn with<F: Future>(&self, f: F) -> TaskLocalFuture<Self, F> {
        KORU_TASK.scope(self.clone(), f)
    }

    pub fn local() -> Self {
        KORU_TASK.with(|t| t.clone())
    }

    pub fn local_or_new() -> Self {
        KORU_TASK
            .try_with(|t| t.clone())
            .unwrap_or_else(|_| Self::default())
    }

    pub fn db_conn() -> db::Conn {
        KORU_TASK.with(|t| t.inner.conn.clone())
    }

    pub fn global() -> Global {
        KORU_TASK.with(|t| t.inner.global.clone())
    }

    pub fn cursor_db() -> remote_cursors::Db {
        KORU_TASK.with(|t| t.inner.global.inner.cursor_db.clone())
    }

    pub fn set_db_url(url: &str) -> Result<(), db::Error> {
        KORU_TASK.with(|t| t.inner.global.inner.db.set_url(url))
    }
}

#[derive(Default)]
struct GlobalInner {
    node: RwLock<Option<KoruNode>>,
    db: db::Manager,
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) same_tran: bool,
    cursor_db: remote_cursors::Db,
}

#[derive(Default, Clone)]
pub struct Global {
    inner: Arc<GlobalInner>,
}
impl Global {
    pub fn add_ts_node(&self, node: KoruNode) {
        let mut guard = self.inner.node.write().expect("should lock");
        *guard = Some(node);
    }

    pub fn node(&self) -> KoruNode {
        let guard = self.inner.node.read().expect("should lock");
        guard.clone().expect("Node not set")
    }
}

#[cfg(test)]
#[path = "task_test.rs"]
mod test;
