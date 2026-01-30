use std::{thread, time::Duration};

use tokio::{sync::oneshot, task::JoinSet};

use crate::{db, node};

pub(crate) async fn timeout(time: u64) {
    let (tx, rx) = oneshot::channel::<()>();
    thread::spawn(move || {
        // This waits 2 real seconds, ignoring Tokio's pause
        thread::sleep(Duration::from_millis(time));
        // If the test hasn't finished, this sends a signal
        let _ = tx.send(());
    });
    let _ = rx.await;
    panic!("Timed out");
}

pub(crate) async fn assert_join_set(mut js: JoinSet<()>, to_ms: u64) {
    js.spawn(timeout(if to_ms == 0 { 500 } else { to_ms }));
    if let Some(Err(err)) = js.join_next().await
        && let Ok(reason) = err.try_into_panic()
    {
        // Resume the panic on the main task
        std::panic::resume_unwind(reason);
    }

    js.shutdown().await;
}

pub(crate) fn set_test_db() {
    let _ = node::Task::set_db_url(&format!(
        "host=/var/run/postgresql dbname=training-simstest user={}",
        env!("USER")
    ));
}

pub(crate) fn start_tran() -> db::Trans {
    set_test_db();
    node::Task::db_conn().begin_transaction().unwrap()
}

pub(crate) async fn async_test<F: Future<Output = crate::Result<()>>>(body: F) {
    node::Task::default().with(body).await.unwrap();
}

pub(crate) async fn same_tran_test<F: Future<Output = crate::Result<()>>>(body: F) {
    node::Task::new_with_same_tran().with(body).await.unwrap();
}
