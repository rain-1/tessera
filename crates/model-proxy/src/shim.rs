//! In-sandbox loopback shim (`tessera-netshim`).
//!
//! Listens on a loopback TCP port inside the sandbox's (otherwise empty)
//! network namespace and splices every accepted connection to the
//! bind-mounted Unix socket of the host-side model proxy. It is *untrusted
//! plumbing*: it runs as the workload, adds no policy and holds no secret.
//! A workload that kills it and binds the port itself reaches nothing more
//! than the same Unix socket. All enforcement is in the proxy.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Semaphore;

/// Most connections spliced at once.
pub const MAX_SHIM_CONNECTIONS: usize = 64;

/// Bind the loopback listener. Non-loopback addresses are refused.
pub async fn bind_loopback(addr: SocketAddr) -> io::Result<TcpListener> {
    if !addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tessera-netshim only listens on loopback addresses",
        ));
    }
    TcpListener::bind(addr).await
}

/// Accept forever, splicing each connection to `socket`.
pub async fn run(listener: TcpListener, socket: PathBuf) -> io::Result<()> {
    let socket = Arc::new(socket);
    let slots = Arc::new(Semaphore::new(MAX_SHIM_CONNECTIONS));
    loop {
        let (mut tcp, _) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            continue; // dropping closes the connection
        };
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            if let Ok(mut unix) = UnixStream::connect(socket.as_path()).await {
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await;
            }
            drop(permit);
        });
    }
}
