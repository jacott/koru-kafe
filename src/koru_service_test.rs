use std::net::Ipv4Addr;

use http::header::HOST;

use super::*;

#[test]
fn https_convert_req() {
    let mut req = Request::builder()
        .uri("https://my.test/a/b/c?abc=123")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    super::convert_req(&mut req, &ip_addr, "other").unwrap();

    let uri = req.uri().to_string();
    assert_eq!(&uri, "/a/b/c?abc=123");

    assert_eq!(req.headers().get(HOST).unwrap(), "my.test");
    assert_eq!(
        req.headers()
            .get(HeaderName::from_static("x-real-ip"))
            .unwrap(),
        "1.2.3.4"
    );
}

#[test]
fn no_authority_convert_req() {
    let mut req = Request::builder()
        .uri("/a/b/c?abc=123")
        .body(Empty::<Bytes>::new())
        .unwrap();
    req.headers_mut()
        .entry(HOST)
        .or_insert(HeaderValue::from_static("foo"));

    let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    super::convert_req(&mut req, &ip_addr, "other").unwrap();

    let uri = req.uri().to_string();
    assert_eq!(&uri, "/a/b/c?abc=123");

    assert_eq!(req.headers().get(HOST).unwrap(), "foo");
    assert_eq!(
        req.headers()
            .get(HeaderName::from_static("x-real-ip"))
            .unwrap(),
        "1.2.3.4"
    );
}
