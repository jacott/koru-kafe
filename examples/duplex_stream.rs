use http_body_util::{combinators::BoxBody, Full};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, service::service_fn};
use hyper::{server::conn::http1, Response};
use hyper::{Request, Result};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    io::{self, AsyncWriteExt as _, DuplexStream},
    join,
};

type MyBody = BoxBody<Bytes, hyper::Error>;

// type Response<B = > = hyper::Response<impl Body>;

// An async function that consumes a request, does nothing with it and returns a
// response.
async fn hello<I>(_req: Request<I>) -> Result<Response<MyBody>>
where
    I: hyper::body::Body + Send + 'static,
    <I as hyper::body::Body>::Data: Send + Sync,
    <I as hyper::body::Body>::Error: Send + Sync + std::error::Error,
{
    let res = Response::new(full(Bytes::from("Hello World!\n")));
    Ok(res)
}

fn full<T: Into<Bytes>>(chunk: T) -> MyBody {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

async fn fetch_url(url: hyper::Uri, stream: DuplexStream) -> Result<()> {
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
        println!("client done\n");
    });

    let authority = url.authority().unwrap().clone();

    let path = url.path();
    let req = Request::builder()
        .uri(path)
        .header(hyper::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())
        .unwrap();

    let mut res = sender.send_request(req).await?;

    println!("Response: {}", res.status());
    println!("Headers: {:#?}\n", res.headers());

    // Stream the body, writing each chunk to stdout as we get it
    // (instead of buffering and printing at the end).
    while let Some(next) = res.frame().await {
        let frame = next?;
        if let Some(chunk) = frame.data_ref() {
            io::stdout().write_all(chunk).await.unwrap();
        }
    }

    println!("\n\nDone!");

    Ok(())
}

#[tokio::main]
pub async fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = "http://localhost:1234/snb/dfsfsd?fsddf=sdfdf";
    let url = url.parse::<hyper::Uri>().unwrap();
    let (client, server) = tokio::io::duplex(5);
    let io = TokioIo::new(server);

    // Spin up a new task in Tokio so we can continue to listen for new TCP connection on the
    // current task without waiting for the processing of the HTTP1 connection we just received
    // to finish
    let server = tokio::task::spawn(async move {
        // Handle the connection from the client using HTTP1 and pass any
        // HTTP requests received on that connection to the `hello` function
        if let Err(err) = http1::Builder::new()
            .timer(TokioTimer::new())
            .serve_connection(io, service_fn(hello))
            .await
        {
            println!("Error serving connection: {:?}", err);
        }
        println!("server done");
    });

    let client = tokio::task::spawn(async move {
        fetch_url(url, client).await.unwrap();
        println!("cccc");
    });

    let _res = join!(server, client);
    print!("+++++++");

    Ok(())
}
