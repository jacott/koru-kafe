use async_trait::async_trait;
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};
use tokio::task::JoinSet;

use crate::node::Task;

pub type DynStartup = dyn Startup + Sync + Send;
pub type RcDynStartup = Arc<DynStartup>;

#[async_trait]
pub trait Startup {
    async fn start(&self);
}

#[derive(Default)]
pub struct StartupDb {
    startups: Vec<RcDynStartup>,
}

lazy_static! {
    static ref STARTUP_DB: Arc<Mutex<StartupDb>> = Arc::new(Mutex::new(StartupDb::default()));
}

impl StartupDb {
    pub fn add(startup: RcDynStartup) {
        STARTUP_DB.lock().unwrap().startups.push(startup);
    }

    pub fn start(js: &mut JoinSet<()>) {
        let startups = &STARTUP_DB.lock().unwrap().startups;
        for su in startups {
            let su = su.clone();
            js.spawn(Task::scope(async move {
                su.start().await;
            }));
        }
    }
}
