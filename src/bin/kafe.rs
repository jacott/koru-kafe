use koru_kafe::{conf, Result};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::mpsc,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cdir = conf::default_cfg()?;

    let (tx, rx) = mpsc::channel(1);

    let mut finished = conf::load_and_monitor(&cdir, rx).await?;

    let mut sig = signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            _ = &mut finished => {
                break;
            }
            _ = sig.recv() => {
                tx.send(()).await?;
            }
        }
    }

    Ok(())
}
