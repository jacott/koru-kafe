use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use canvas::CanvasDb;

use crate::id::Id;

pub mod canvas;
pub mod message;

#[derive(Default, Clone)]
pub struct Db(Arc<RwLock<HashMap<u64, CanvasDb>>>);
impl Db {
    pub fn get_canvas_db(&self, db_id: u64) -> CanvasDb {
        if let Some(db) = self.0.read().expect("poisoned").get(&db_id) {
            db.clone()
        } else {
            let mut guard = self.0.write().expect("poisoned");
            let mut is_new = false;
            let db = guard
                .entry(db_id)
                .or_insert_with(|| {
                    is_new = true;
                    CanvasDb::new(db_id)
                })
                .clone();
            if is_new {
                crate::info!("new DB {} {}", Id::from(db_id as u128), guard.len());
            }
            db
        }
    }

    pub fn remove_db_if_empty(&self, db_id: u64) {
        let mut guard = self.0.write().expect("poisoned");
        if let Some(canvas_db) = guard.get(&db_id)
            && canvas_db.is_empty()
        {
            guard.remove(&db_id);
            crate::info!("close DB {} {}", Id::from(db_id as u128), guard.len());
        }
    }
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod test;
