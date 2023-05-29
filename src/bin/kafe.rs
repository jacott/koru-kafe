use koru_kafe::{conf, listener, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let (tls_map, psl_map) = conf::load()?;
    let mut handles = Vec::with_capacity(psl_map.len());

    for (addr, domains) in tls_map {
        println!("TLS Server started, listening on {}", addr);

        handles.push(tokio::task::spawn(async move {
            listener::tls_listen(addr, domains).await.unwrap();
        }));
    }

    for (addr, domains) in psl_map {
        println!("Http/1 Server started, listening on {}", addr);
        handles.push(tokio::task::spawn(async move {
            listener::listen(addr, domains).await.unwrap();
        }));
    }

    for handle in handles {
        handle.await?;
    }

    Ok(())
}
