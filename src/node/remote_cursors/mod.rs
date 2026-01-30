use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use canvas::CanvasDb;

pub mod canvas;
pub mod message;

#[derive(Default, Clone)]
pub struct Db(Arc<RwLock<HashMap<u64, CanvasDb>>>);
impl Db {
    pub fn get_canvas_db(&self, db_id: u64) -> CanvasDb {
        if let Some(db) = self.0.read().expect("poisoned").get(&db_id) {
            db.clone()
        } else {
            self.0
                .write()
                .expect("poisoned")
                .entry(db_id)
                .or_default()
                .clone()
        }
    }
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod test;
