//! `tessera-netshim` byte forwarding.

use tessera_model_proxy::shim;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener};

#[tokio::test]
async fn forwards_bytes_both_ways_with_half_close() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("echo.sock");
    let ul = UnixListener::bind(&sock).unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = ul.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    let l = shim::bind_loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(shim::run(l, sock));

    let data: Vec<u8> = (0..1_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let data = data.clone();
        tasks.push(tokio::spawn(async move {
            let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let (mut r, mut w) = tcp.into_split();
            let writer = tokio::spawn(async move {
                w.write_all(&data).await.unwrap();
                w.shutdown().await.unwrap();
            });
            let mut out = Vec::new();
            r.read_to_end(&mut out).await.unwrap();
            writer.await.unwrap();
            out
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), data);
    }
}

#[tokio::test]
async fn refuses_non_loopback() {
    assert!(
        shim::bind_loopback("0.0.0.0:0".parse().unwrap())
            .await
            .is_err()
    );
}
