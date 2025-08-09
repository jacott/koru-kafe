use http::Request;

use crate::test_util;

use super::*;
use std::net::Ipv4Addr;

struct Foo;

#[async_trait]
impl Location for Foo {
    async fn connect(&self, _domain: Domain, req: crate::Req, _ip_addr: IpAddr, _count: u16) -> crate::ResultResp {
        let ans = tokio::join!(tokio::task::spawn(async move { req }));
        let req = ans.0.unwrap();
        Ok(crate::resp(
            200,
            Bytes::from(format!("hello {:?} {}", req.method(), req.uri())),
        ))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[tokio::test]
async fn connect() {
    let d: Domain = Default::default();
    d.write_state()
        .location_prefixes
        .insert("/".to_string(), Arc::new(Foo {}));

    let req = crate::Request::new(test_util::build_incoming_body(Bytes::new()).await.unwrap());
    let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    let resp = d.find_location("/").unwrap().connect(d, req, ip_addr, 0).await.unwrap();
    let whole_body = resp.collect().await.unwrap().to_bytes();
    assert_eq!(whole_body, "hello GET /");
}

#[tokio::test]
async fn rewrite() {
    let d: Domain = Default::default();
    d.write_state()
        .locations
        .insert("/index.html".to_string(), Arc::new(Foo {}));
    d.write_state().location_prefixes.insert(
        "/".to_string(),
        Arc::new(Rewrite {
            path: "/index.html".to_string(),
        }),
    );

    let body = test_util::build_incoming_body(Bytes::new()).await.unwrap();
    let req = Request::builder().uri("http://localhost/?abc=123").body(body).unwrap();
    let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    let resp = d.find_location("/").unwrap().connect(d, req, ip_addr, 0).await.unwrap();
    let whole_body = resp.collect().await.unwrap().to_bytes();

    assert_eq!(whole_body, "hello GET http://localhost/index.html?abc=123");
}

#[tokio::test]
async fn redirect() -> crate::Result<()> {
    let d: Domain = Default::default();

    d.write_state().location_prefixes.insert(
        "/".to_string(),
        Arc::new(Redirect {
            code: StatusCode::MOVED_PERMANENTLY,
            scheme: Some("https".to_string()),
            ..Default::default()
        }),
    );

    let d2 = d.clone();

    {
        let req = Request::builder()
            .uri("http://localhost/a/b/c?abc=123")
            .body(test_util::build_incoming_body(Bytes::new()).await.unwrap())
            .unwrap();
        let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let resp = d.find_location("/").unwrap().connect(d, req, ip_addr, 0).await.unwrap();

        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            String::from_utf8(resp.headers().get(header::LOCATION).unwrap().as_bytes().to_vec())?.as_str(),
            "https://localhost/a/b/c?abc=123"
        );
        let whole_body = resp.collect().await.unwrap().to_bytes();

        assert_eq!(whole_body, "");
    }

    let d = d2;

    {
        let req = Request::builder()
            .header("Host", "test.nz")
            .uri("/a/b/c?abc=123")
            .body(test_util::build_incoming_body(Bytes::new()).await.unwrap())
            .unwrap();
        let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let resp = d.find_location("/").unwrap().connect(d, req, ip_addr, 0).await.unwrap();

        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            String::from_utf8(resp.headers().get(header::LOCATION).unwrap().as_bytes().to_vec())?.as_str(),
            "https://test.nz/a/b/c?abc=123"
        );
        let whole_body = resp.collect().await.unwrap().to_bytes();

        assert_eq!(whole_body, "");
    }

    Ok(())
}
