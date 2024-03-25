use http_body_util::BodyExt;
use http_body_util::{combinators::BoxBody, Full};
use hyper::{
    body::{Body, Bytes},
    service::service_fn,
};
use hyper::{server::conn::http1, Response};
use hyper::{Request, Result};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

type MyBody = BoxBody<Bytes, hyper::Error>;

// type Response<B = > = hyper::Response<impl Body>;

// An async function that consumes a request, does nothing with it and returns a
// response.
async fn hello<I>(mut req: Request<I>) -> Result<Response<MyBody>>
where
    I: hyper::body::Body + Send + 'static,
    <I as hyper::body::Body>::Data: Send + Sync,
    <I as hyper::body::Body>::Error: Send + Sync + std::error::Error,
{
    if req.is_end_stream() {
        let res = Response::new(full(Bytes::from("Hello World!")));
        return Ok(res);
    }
    let out_addr: SocketAddr = ([127, 0, 0, 1], 3000).into();
    let uri_string = format!(
        "http://{}{}",
        out_addr,
        req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
    );
    let uri = uri_string.parse().unwrap();
    *req.uri_mut() = uri;

    let host = req.uri().host().expect("uri has no host");
    let port = req.uri().port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    let client_stream = TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(client_stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let web_res = sender.send_request(req).await?;

    let (parts, body) = web_res.into_parts();
    Ok(Response::from_parts(parts, body.boxed()))
}

fn full<T: Into<Bytes>>(chunk: T) -> MyBody {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

#[tokio::main]
pub async fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This address is localhost
    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

    // Bind to the port and listen for incoming TCP connections
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);
    loop {
        // When an incoming TCP connection is received grab a TCP stream for
        // client<->server communication.
        //
        // Note, this is a .await point, this loop will loop forever but is not a busy loop. The
        // .await point allows the Tokio runtime to pull the task off of the thread until the task
        // has work to do. In this case, a connection arrives on the port we are listening on and
        // the task is woken up, at which point the task is then put back on a thread, and is
        // driven forward by the runtime, eventually yielding a TCP stream.
        let (tcp, _) = listener.accept().await?;
        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(tcp);

        // Spin up a new task in Tokio so we can continue to listen for new TCP connection on the
        // current task without waiting for the processing of the HTTP1 connection we just received
        // to finish
        tokio::task::spawn(async move {
            // Handle the connection from the client using HTTP1 and pass any
            // HTTP requests received on that connection to the `hello` function
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(io, service_fn(hello))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
