use argh::FromArgs;
use koru_kafe::{
    conf::{self, ConfSig},
    Result,
};
use std::path::Path;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::mpsc,
};

#[derive(Debug, FromArgs)]
/// Koru Accerlerated Front End web server
struct Opts {
    /// print the version of kafe
    #[argh(switch)]
    version: bool,

    /// the directory where config files are found
    #[argh(option)]
    config: Option<String>,

    /// test that this build of kafe matches the commit id
    #[argh(option)]
    is_commit: Option<String>,
}

static VERSION: &str = std::include_str!("../version.txt");

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = argh::from_env();
    if let Some(id) = opts.is_commit {
        if id == VERSION.split(':').next_back().unwrap().trim() {
            if opts.config.is_none() {
                std::process::exit(0);
            }
        } else {
            eprintln!("commit tag differs");
            std::process::exit(1);
        }
    }

    if opts.version {
        println!("{}", VERSION.split(':').next().unwrap());
        return Ok(());
    }

    if opts.config.is_none() {
        eprintln!("Missing config option; see --help");
        std::process::exit(1);
    }

    let cdir = opts.config.unwrap();
    let cdir = Path::new(&cdir);

    let (tx, rx) = mpsc::channel(1);
    let tx2 = tx.clone();
    let finished = conf::load_and_monitor(cdir, rx).await?;

    let mut sig_reload = signal(SignalKind::hangup())?;

    tokio::spawn(async move {
        while sig_reload.recv().await.is_some() {
            if tx.send(ConfSig::Term).await.is_err() {
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
