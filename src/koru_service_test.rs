use std::net::Ipv4Addr;

use http::header::HOST;

use super::*;

#[test]
fn convert_uri() {
    let req = Request::builder()
        .uri("http://localhost/a/b/c?abc=123")
        .body("")
        .unwrap();

    assert_eq!(super::convert_uri(req.uri(), "test"), "test/a/b/c?abc=123");
}

#[test]
fn convert_req() {
    let mut req = Request::builder()
        .uri("http://localhost/a/b/c?abc=123")
        .body(Empty::<Bytes>::new())
        .unwrap();
    req.headers_mut()
        .entry(HOST)
        .or_insert(HeaderValue::from_static("foo"));

    let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    super::convert_req(&mut req, &ip_addr).unwrap();

    assert_eq!(req.headers().get(HOST).unwrap(), "foo");
    assert_eq!(
        req.headers()
            .get(HeaderName::from_static("x-real-ip"))
            .unwrap(),
        "1.2.3.4"
    );
}
