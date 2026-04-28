// use super::*;

use std::{path::Path, time::UNIX_EPOCH};

use crate::domain::Redirect;

fn s(v: &str) -> String {
    v.to_string()
}

#[test]
fn load_from() -> crate::Result<()> {
    let cb = super::load_from(Path::new("tests/config"), UNIX_EPOCH)?.0;
    assert_eq!(cb.len(), 2);

    let ds = cb.get("[::]:8088").unwrap();
    let (n, d) = ds.iter().next().unwrap();
    assert_eq!(n, "*");

    let rd = d.find_location("/abc/123").unwrap();
    let rd = rd.as_any().downcast_ref::<Redirect>().unwrap();

    assert_eq!(rd.code, 301);
    assert_eq!(rd.scheme, Some("https".to_string()));
    assert_eq!(rd.path, None);

    let ds = cb.get("localhost:8080").unwrap();

    let (n, d) = ds.iter().next().unwrap();
    assert_eq!(n, "localhost");
    let service = d.get_service("app").unwrap();
    assert_eq!(
        service.cmd,
        Some((
            s("my-test-cmd"),
            s("../cmd-name"),
            vec![s("arg1"), s("arg2")]
        ))
    );
    assert_eq!(service.server_socket, "localhost:3000");

    let v1 = d.find_location("/ws/123").unwrap();
    let v2 = d.find_location("/rc").unwrap();

    assert_eq!(format!("{v1:?}"), format!("{v2:?}"));

    Ok(())
}

#[test]
fn to_arg_list() -> crate::Result<()> {
    let yaml = yaml_rust::YamlLoader::load_from_str(
        r#"[1, 2, "th$r}ee", "f{ou}r${PWD}f$ve${HOME}", "${HOME}"] "#,
    )?;
    let yaml = yaml[0].as_vec().unwrap();

    let exp = vec![
        "1".to_string(),
        "2".to_string(),
        "th$r}ee".to_string(),
        format!(
            "f{2}r{0}f$ve{1}",
            std::env::var("PWD")?,
            std::env::var("HOME")?,
            "{ou}"
        ),
        std::env::var("HOME")?,
    ];

    let ans = super::to_env_string_list(yaml).unwrap();

    assert_eq!(ans, exp);
    Ok(())
}
