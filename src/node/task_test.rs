use tokio::task::JoinSet;

use crate::test_helper;

use super::*;

#[tokio::test]
async fn db_conn() {
    test_helper::async_test(async {
        let mut jset = JoinSet::new();

        test_helper::set_test_db();

        for _ in 0..1 {
            jset.spawn(Task::scope(async {
                {
                    {
                        let conn = Task::db_conn();
                        let conn2 = Task::db_conn();

                        conn.execute("BEGIN", &[]).await.unwrap();
                        conn2
                            .execute(
                                r#"insert into "Game" (_id) values ($1::TEXT)"#,
                                &[&"game123"],
                            )
                            .await
                            .unwrap();
                    }

                    Task::scope(async {
                        let conn = Task::db_conn();
                        let row = conn.query(r#"select _id from "Game""#, &[]).await.unwrap();
                        assert_eq!(row.len(), 0);
                    })
                    .await;

                    {
                        let conn = Task::db_conn();
                        let row = conn
                            .query_opt(r#"select _id from "Game""#, &[])
                            .await
                            .unwrap()
                            .unwrap();
                        let two: String = row.try_get(0).unwrap();
                        assert_eq!(&two, "game123");
                    }
                }
            }));
        }

        test_helper::assert_join_set(jset, 500).await;
        Ok(())
    })
    .await;
}
