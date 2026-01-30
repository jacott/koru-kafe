use super::*;

#[test]
fn id() {
    let mut r = Random::new(&["hello".as_bytes(), "world".as_bytes()]);

    assert_eq!(r.id().as_str(), "NTuiM1uEZR7vz2Nd5");
}
