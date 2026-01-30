use crate::{node::Task, test_helper};

use super::*;

fn conn_str() -> String {
    format!("host=/var/run/postgresql user={}", env!("USER"))
}

#[tokio::test]
async fn new_pool() -> crate::Result<()> {
    let pool: ConnectionPool = super::new_pool(&conn_str()).await?;
    let conn = pool.get().await?;
    let row = conn.query_opt(r##"select 1 + 1;"##, &[]).await?.unwrap();
    let two: i32 = row.try_get(0)?;
    assert_eq!(two, 2);
    Ok(())
}

#[tokio::test]
async fn begin_transaction_aborts() {
    test_helper::async_test(async {
        test_helper::set_test_db();
        let dbx = Task::db_conn();
        {
            let _tran = dbx.begin_transaction();
            dbx.execute("create table foo1 (a text)", &[]).await?;
            dbx.execute("insert into foo1 (a) values ($1)", &[&"abc"]).await?;
            assert!(dbx.is_in_trans(), "should be in in transaction");
            {
                let _tran = dbx.begin_transaction();
                dbx.execute("insert into foo1 (a) values ($1)", &[&"def"]).await?;
                assert!(dbx.is_in_trans(), "should be in in transaction");
                let v = dbx.query("select a from foo1", &[]).await?.len();
                assert_eq!(v, 2);
            }
            assert!(dbx.is_in_trans(), "should be in in transaction");

            let v = dbx.query("select a from foo1", &[]).await?.len();
            assert_eq!(v, 1);
        }
        assert!(!dbx.is_in_trans(), "should be out of transaction");
        let v = dbx.query("select a from foo1", &[]).await;
        assert!(v.is_err());
        if let Err(v) = v {
            assert_eq!(v.to_string(), "db::Error db error".to_string());
        }
        assert!(!dbx.is_in_trans(), "should be out of transaction");

        Ok(())
    })
    .await;
}

#[tokio::test]
async fn commit() {
    test_helper::async_test(async {
        test_helper::set_test_db();
        let db1 = Task::db_conn();
        db1.execute("drop table if exists foo2", &[]).await?;
        db1.execute("create table foo2 (a text)", &[]).await?;
        let db2 = Conn::new(db1.inner.manager.clone());
        {
            let tran = db1.begin_transaction()?;
            {
                let tran = db1.begin_transaction()?;
                db1.execute("insert into foo2 (a) values ($1)", &[&"abc"]).await?;
                let v = db2.query("select a from foo2", &[]).await?.len();
                assert_eq!(v, 0);
                tran.commit().await?;
            }
            tran.commit().await?;
        }
        let v = db2.query("select a from foo2", &[]).await?.len();

        assert_eq!(v, 1);

        db1.execute("drop table if exists foo2", &[]).await?;

        Ok(())
    })
    .await;
}
