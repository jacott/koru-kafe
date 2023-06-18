use koru_kafe::{conf, Result};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::mpsc,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cdir = conf::default_cfg()?;

    let (tx, rx) = mpsc::channel(1);
    let finished = conf::load_and_monitor(&cdir, rx).await?;

    let mut sig = signal(SignalKind::user_defined1())?;

    tokio::spawn(async move {
        while sig.recv().await.is_some() {
            if tx.send(()).await.is_err() {
                break;
            }
        }
    });

    finished.await?;

    Ok(())
}
