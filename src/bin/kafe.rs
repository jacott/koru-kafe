use koru_kafe::{
    conf::{self, ConfSig},
    Result,
};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::mpsc,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cdir = conf::default_cfg()?;

    let (tx, rx) = mpsc::channel(1);
    let finished = conf::load_and_monitor(&cdir, rx).await?;

    let mut sig_reload = signal(SignalKind::user_defined1())?;

    let tx2 = tx.clone();

    tokio::spawn(async move {
        while sig_reload.recv().await.is_some() {
            if tx.send(ConfSig::Reload).await.is_err() {
                break;
            }
        }
    });

    let mut sig_term = signal(SignalKind::terminate())?;
    tokio::spawn(async move {
        while sig_term.recv().await.is_some() {
            if tx2.send(ConfSig::Term).await.is_err() {
                break;
            }
        }
    });

    finished.await?;

    Ok(())
}
