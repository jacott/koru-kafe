use hyper::Body;
use hyper::Response;
use tokio::fs;

pub async fn send_file(path: &str) -> crate::Result<Response<Body>> {
    let path = if path == "/" {
        String::from("iat/index.html")
    } else {
        format!("{}{}", if path.starts_with("/index.") { "iat" } else { "app" }, path)
    };
    match fs::read(&path).await {
        Ok(body) => Ok(Response::builder()
            .status(200)
            .header(
                "Content-Type",
                mime_guess::from_path(&path).first_or_text_plain().to_string(),
            )
            .body(Body::from(body))?),
        Err(_) => {
            eprintln!("{} 404", &path);
            Ok(Response::builder().status(404).body(Body::from("Not found"))?)
        }
    }
}
