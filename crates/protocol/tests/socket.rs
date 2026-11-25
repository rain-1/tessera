//! Client/server over real Unix socket pairs; peer credentials.

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::thread;

use tessera_protocol::bounded::BoundedString;
use tessera_protocol::frame::FrameLimits;
use tessera_protocol::unix::{
    CheckedStream, peer_credentials, recv_packet, send_packet, seqpacket_pair,
};
use tessera_protocol::*;

fn answer(req: &Request) -> Response {
    match req {
        Request::Inspect { .. } => Response::Error {
            request_id: None,
            code: ErrorCode::UnknownCapability,
            detail: BoundedString::new("no such capability").unwrap(),
        },
        Request::Drop { request_id, .. } => Response::Dropped {
            request_id: *request_id,
        },
        other => Response::Error {
            request_id: other.request_id(),
            code: ErrorCode::PermissionDenied,
            detail: BoundedString::default(),
        },
    }
}

fn requests() -> Vec<ClientMessage> {
    vec![
        ClientMessage {
            correlation_id: 1,
            request: Request::Inspect { cap_id: 42 },
        },
        ClientMessage {
            correlation_id: 2,
            request: Request::Drop {
                request_id: 10,
                cap_id: 42,
            },
        },
        ClientMessage {
            correlation_id: 3,
            request: Request::Consume {
                request_id: 11,
                cap_id: 42,
                operation: WireOperation::FileReplaceContent {
                    bytes: vec![7u8; 100_000].try_into().unwrap(),
                },
            },
        },
    ]
}

#[test]
fn client_server_over_stream_socketpair() {
    let (client, server) = UnixStream::pair().unwrap();
    let limits = FrameLimits::default();
    let srv = thread::spawn(move || {
        let fd = server.as_fd();
        let mut rd = CheckedStream::new(fd);
        let mut wr = &server;
        let mut n = 0;
        while let Some(msg) = recv_message::<_, ClientMessage>(&mut rd, limits).unwrap() {
            let resp = ServerMessage {
                correlation_id: msg.correlation_id,
                response: answer(&msg.request),
            };
            send_message(&mut wr, &resp, limits).unwrap();
            n += 1;
        }
        n
    });
    let mut c = &client;
    for msg in requests() {
        send_message(&mut c, &msg, limits).unwrap();
        let resp: ServerMessage = recv_message(&mut c, limits).unwrap().unwrap();
        assert_eq!(resp.correlation_id, msg.correlation_id);
        assert_eq!(resp.response, answer(&msg.request));
    }
    client.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(srv.join().unwrap(), 3);
}

#[test]
fn client_server_over_seqpacket() {
    let (client, server) = seqpacket_pair().unwrap();
    let limits = FrameLimits::default();
    let srv = thread::spawn(move || {
        let mut n = 0;
        while let Some(p) = recv_packet(&server, limits).unwrap() {
            let msg = decode_client(&p, limits.max_frame()).unwrap();
            let resp = ServerMessage {
                correlation_id: msg.correlation_id,
                response: answer(&msg.request),
            };
            send_packet(&server, &encode_server(&resp).unwrap(), limits).unwrap();
            n += 1;
        }
        n
    });
    for msg in requests() {
        send_packet(&client, &encode_client(&msg).unwrap(), limits).unwrap();
        let p = recv_packet(&client, limits).unwrap().unwrap();
        let resp = decode_server(&p, limits.max_frame()).unwrap();
        assert_eq!(resp.correlation_id, msg.correlation_id);
        assert_eq!(resp.response, answer(&msg.request));
    }
    drop(client);
    assert_eq!(srv.join().unwrap(), 3);
}

#[test]
fn oversized_seqpacket_discarded_then_stream_continues() {
    let (a, b): (OwnedFd, OwnedFd) = seqpacket_pair().unwrap();
    let big = vec![1u8; 5000];
    send_packet(&a, &big, FrameLimits::new(10_000)).unwrap();
    send_packet(&a, b"ok", FrameLimits::new(10_000)).unwrap();
    match recv_packet(&b, FrameLimits::new(4096)) {
        Err(FrameError::TooLarge { len, max }) => {
            assert_eq!((len, max), (5000, 4096));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(
        recv_packet(&b, FrameLimits::new(4096)).unwrap().unwrap(),
        b"ok"
    );
}

#[test]
fn peer_credentials_of_socketpair_are_ours() {
    let (a, _b) = UnixStream::pair().unwrap();
    let c = peer_credentials(&a).unwrap();
    assert_eq!(c.pid as u32, std::process::id());
    assert_eq!(c.uid, rustix::process::geteuid().as_raw());
    assert_eq!(c.gid, rustix::process::getegid().as_raw());
}
