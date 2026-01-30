use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Buf;
use pretty_assertions::{assert_eq, assert_matches};
use serde_json::json;

use crate::{
    id::Id,
    message::{Decoder, Encoder, GlobalDictEncoder, jst},
    node, test_helper, test_util,
};

use super::*;

#[tokio::test]
async fn start() {
    test_helper::same_tran_test(async {
        let koru_node = node::KoruNode::new("test/uds".to_owned());
        let _ = test_util::set_init_msg(&koru_node);
        node::Task::global().add_ts_node(koru_node.clone());

        let tran = test_helper::start_tran();
        let dbx = tran.clone_conn();

        dbx.execute(
            r#"create table "Foo1" (_id text, "createdAt" timestamp, config jsonb)"#,
            &[],
        )
        .await?;

        let t = SystemTime::now();

        let j: Jst = json!({"abc": [123, true]}).try_into().unwrap();

        dbx.execute(
            r#"insert into "Foo1" (_id, "createdAt", "config") values
 ($1::TEXT, $2::TIMESTAMP, $3::jsonb)"#,
            &[&"foo123", &t, &j],
        )
        .await
        .unwrap();

        let id: Id = "foo123".into();
        let row = Model::find_by_id("Foo1", &id).await.unwrap().unwrap();

        let mut gde = GlobalDictEncoder::default();
        let gdd = gde.encode();
        let mut enc = Encoder::message(b'W', &gde);
        row.encode(&mut enc);

        let mut result = enc.encode();
        result.get_u8();

        let mut dec = Decoder::new(result, &gdd);
        assert_matches!(dec.next().unwrap(), Jst::Array);
        assert_eq!(dec.next_into::<String>().unwrap(), "A".to_owned());
        assert_matches!(dec.next().unwrap(), Jst::Array);
        assert_eq!(dec.next_into::<String>().unwrap(), "Foo1".to_owned());
        assert_matches!(dec.next(), Some(Jst::Object));
        let obj = dec.read_object().unwrap();
        let id: String = obj.get("_id").unwrap();
        let created_at: Duration = obj.get("createdAt").unwrap();
        let config: jst::Object = obj.get("config").unwrap();
        assert_eq!(&id, "foo123");
        assert_eq!(
            created_at.as_millis(),
            t.duration_since(UNIX_EPOCH).unwrap().as_millis()
        );
        let jsto = j.try_into().unwrap();
        assert_eq!(&config, &jsto);
        let v: jst::Array = config.get("abc").unwrap();
        let v: i64 = v.get(0).unwrap();
        assert_eq!(v, 123);

        assert_matches!(dec.next().unwrap(), Jst::EndObject);
        assert_matches!(dec.next().unwrap(), Jst::EndObject);

        assert_matches!(dec.next(), None);
        Ok(())
    })
    .await;
}
