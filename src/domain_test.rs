use super::*;
use hyper::body::to_bytes;
use std::net::Ipv4Addr;

struct Foo;

#[async_trait]
impl Location for Foo {
    async fn connect(
        &self,
        _domain: Domain,
        req: Request<Body>,
        _ip_addr: IpAddr,
        _count: u16,
    ) -> crate::Result<Response<Body>> {
        let ans = tokio::join!(tokio::task::spawn(async move { req }));
        let req = ans.0.unwrap();
        Ok(Response::builder()
            .body((format!("hello {:?} {}", req.method(), req.uri())).into())
            .unwrap())
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

    let req = Default::default();
    let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    let resp = d.find_location("/").unwrap().connect(d, req, ip_addr, 0).await.unwrap();

    assert_eq!(to_bytes(resp.into_body()).await.unwrap(), "hello GET /");
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

    let req = Request::builder()
        .uri("http://localhost/?abc=123")
        .body(Body::empty())
        .unwrap();
    let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    let resp = d.find_location("/").unwrap().connect(d, req, ip_addr, 0).await.unwrap();

    assert_eq!(
        to_bytes(resp.into_body()).await.unwrap(),
        "hello GET http://localhost/index.html?abc=123"
    );
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

    let req = Request::builder()
        .uri("http://localhost/a/b/c?abc=123")
        .body(Body::empty())
        .unwrap();
    let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    let resp = d.find_location("/").unwrap().connect(d, req, ip_addr, 0).await.unwrap();

    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        String::from_utf8(resp.headers().get(header::LOCATION).unwrap().as_bytes().to_vec())?.as_str(),
        "https://localhost/a/b/c?abc=123"
    );

    assert_eq!(to_bytes(resp.into_body()).await.unwrap(), "");

    Ok(())
}
