use std::fmt;

use bytes::Bytes;
use tokio_postgres::Row;

use crate::{Jst, db::Error, message::Encoder, node::Task};

pub struct ModelRow(Bytes, Row);
impl ModelRow {
    pub fn encode(&self, encoder: &mut Encoder) {
        let cols = cols_as_bytes(&self.1);
        encode_row(encoder, self.0.clone(), &self.1, &cols);
    }
}

pub struct ModelVec(Bytes, Vec<Row>);
impl ModelVec {
    pub fn encode(&self, encoder: &mut Encoder) {
        let Some((row, rest)) = self.1.split_first() else {
            return;
        };
        let cols = cols_as_bytes(row);
        encode_row(encoder, self.0.clone(), row, &cols);
        for row in rest {
            encode_row(encoder, self.0.clone(), row, &cols);
        }
    }
}

fn cols_as_bytes(row: &Row) -> Vec<Bytes> {
    row.columns()
        .iter()
        .map(|c| Bytes::copy_from_slice(c.name().as_bytes()))
        .collect()
}

fn encode_row(encoder: &mut Encoder, model: Bytes, row: &Row, cols: &[Bytes]) {
    encoder.add(&Jst::Array);
    encoder.add_into("A");
    encoder.add(&Jst::Array);
    encoder.add(&Jst::String(model));
    encoder.add(&Jst::Object);
    for (i, col) in cols.iter().enumerate() {
        if let Some(v) = row.get(i) {
            encoder.add(&Jst::key(col.clone()));
            encoder.add(&v);
        }
    }
    encoder.add(&Jst::EndObject);
    encoder.add(&Jst::EndObject);
    encoder.add(&Jst::EndObject);
}

pub struct Model;
impl Model {
    pub async fn find_by_id(
        model: &'static str,
        id: impl fmt::Display,
    ) -> Result<Option<ModelRow>, Error> {
        let conn = Task::db_conn();
        conn.query_opt(
            &format!(r#"select * from "{model}" where _id = $1::TEXT"#),
            &[&id.to_string().as_str()],
        )
        .await
        .map(|s| s.map(|row| ModelRow(Bytes::from_static(model.as_bytes()), row)))
    }
}

#[cfg(test)]
#[path = "model_test.rs"]
mod test;
