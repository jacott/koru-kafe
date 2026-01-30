use argh::FromArgs;
use koru_kafe::{
    Result,
    conf::{self, ConfSig, LocationBuilders},
};
use koru_kafe::{
    conf::{DbBuilder, TsNodeBuilder},
    node::Task,
    startup::StartupDb,
};
use std::{path::Path, sync::Arc};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    sync::mpsc,
    task::JoinSet,
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

    tracing_subscriber::fmt::init();

    conf::ConfBuilders::add("db", Arc::new(DbBuilder));

    LocationBuilders::add("koru_node", Arc::new(TsNodeBuilder));
    conf::ConfBuilders::add("koru_node", Arc::new(TsNodeBuilder));

    Task::default()
        .with(async move {
            let cdir = opts.config.unwrap();
            let cdir = Path::new(&cdir);

            let (tx, rx) = mpsc::channel(1);
            let finished = conf::load_and_monitor(cdir, rx).await?;

            let mut js = JoinSet::new();

            StartupDb::start(&mut js);

            js.spawn(on_sig_term(signal(SignalKind::hangup())?, tx.clone()));
            js.spawn(on_sig_term(signal(SignalKind::terminate())?, tx));

            finished.await?;

            koru_kafe::info!("Shutdown");
            js.shutdown().await;

            Ok(())
        })
        .await
}

async fn on_sig_term(mut sig: Signal, tx: mpsc::Sender<ConfSig>) {
    while sig.recv().await.is_some() {
        if tx.send(ConfSig::Term).await.is_err() {
            break;
        }
    }
}
