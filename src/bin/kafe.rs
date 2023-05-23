use koru_kafe::{conf, listener, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let listener_map = conf::load()?;
    let mut handles = Vec::with_capacity(listener_map.len());

    for (addr, domains) in listener_map {
        handles.push(tokio::task::spawn(async move {
            listener::listen(addr, domains).await.unwrap();
        }));
    }

    for handle in handles {
        handle.await?;
    }

    Ok(())
}
