//! Mock broker for SDK tests: the server end of a socketpair, decoding
//! client messages strictly with `tessera-protocol` and replying from a
//! scripted handler.

#![allow(dead_code)]

use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tessera_protocol::frame::HARD_MAX_FRAME;
use tessera_protocol::unix::{
    CheckedStream, recv_packet, send_packet, seqpacket_pair, stream_pair,
};
use tessera_protocol::{
    ClientMessage, FrameLimits, Response, ServerMessage, decode_client, encode_server, read_frame,
    write_frame,
};
use tessera_sdk::{Client, ClientConfig};

/// One message the broker received: raw payload and strict decoding.
#[derive(Debug, Clone)]
pub struct Received {
    pub raw: Vec<u8>,
    pub msg: ClientMessage,
}

/// What the handler wants the broker to do.
pub enum Reply {
    /// Answer with this response to the received correlation id.
    Respond(Response),
    /// Send an arbitrary server message (for example with another
    /// correlation id).
    Message(ServerMessage),
    /// Send raw payload bytes.
    Raw(Vec<u8>),
    /// Close the channel.
    Close,
    /// Pause before the next reply.
    Sleep(std::time::Duration),
}

pub type Log = Arc<Mutex<Vec<Received>>>;

pub struct Mock {
    pub client: Client,
    pub log: Log,
    pub thread: Option<JoinHandle<()>>,
}

impl Mock {
    pub fn received(&self) -> Vec<Received> {
        self.log.lock().unwrap().clone()
    }

    pub fn requests(&self) -> Vec<tessera_protocol::Request> {
        self.received().into_iter().map(|r| r.msg.request).collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Seqpacket,
    Stream,
}

fn limits() -> FrameLimits {
    FrameLimits::new(HARD_MAX_FRAME)
}

fn send_raw(fd: &OwnedFd, kind: Kind, payload: &[u8]) -> bool {
    match kind {
        Kind::Seqpacket => send_packet(fd, payload, limits()).is_ok(),
        Kind::Stream => {
            let mut s = std::os::unix::net::UnixStream::from(fd.try_clone().unwrap());
            write_frame(&mut s, payload, limits()).is_ok()
        }
    }
}

/// Serve `server` with `handler` on a background thread until the client
/// hangs up or the handler asks to close.
pub fn serve<H>(server: OwnedFd, kind: Kind, log: Log, mut handler: H) -> JoinHandle<()>
where
    H: FnMut(&ClientMessage) -> Vec<Reply> + Send + 'static,
{
    std::thread::spawn(move || {
        loop {
            let payload = match kind {
                Kind::Seqpacket => match recv_packet(&server, limits()) {
                    Ok(Some(p)) => p,
                    _ => return,
                },
                Kind::Stream => {
                    let mut r = CheckedStream::new(std::os::fd::AsFd::as_fd(&server));
                    match read_frame(&mut r, limits()) {
                        Ok(Some(p)) => p,
                        _ => return,
                    }
                }
            };
            // Strict, canonical decoding: the SDK must produce exactly the
            // bytes a broker accepts.
            let msg = decode_client(&payload, HARD_MAX_FRAME).expect("SDK sent an invalid message");
            log.lock().unwrap().push(Received {
                raw: payload,
                msg: msg.clone(),
            });
            for reply in handler(&msg) {
                let bytes = match reply {
                    Reply::Respond(response) => encode_server(&ServerMessage {
                        correlation_id: msg.correlation_id,
                        response,
                    })
                    .unwrap(),
                    Reply::Message(m) => encode_server(&m).unwrap(),
                    Reply::Raw(b) => b,
                    Reply::Close => return,
                    Reply::Sleep(d) => {
                        std::thread::sleep(d);
                        continue;
                    }
                };
                if !send_raw(&server, kind, &bytes) {
                    return;
                }
            }
        }
    })
}

/// Start a mock over a fresh socketpair of the given kind.
pub fn start_kind<H>(kind: Kind, config: ClientConfig, handler: H) -> Mock
where
    H: FnMut(&ClientMessage) -> Vec<Reply> + Send + 'static,
{
    let (client_fd, server_fd) = match kind {
        Kind::Seqpacket => seqpacket_pair().unwrap(),
        Kind::Stream => stream_pair().unwrap(),
    };
    let log: Log = Arc::default();
    let thread = serve(server_fd, kind, log.clone(), handler);
    let client = Client::from_fd_with(client_fd, config).unwrap();
    Mock {
        client,
        log,
        thread: Some(thread),
    }
}

/// Start a seqpacket mock with a short timeout.
pub fn start<H>(handler: H) -> Mock
where
    H: FnMut(&ClientMessage) -> Vec<Reply> + Send + 'static,
{
    start_kind(Kind::Seqpacket, fast_config(), handler)
}

pub fn fast_config() -> ClientConfig {
    ClientConfig {
        call_timeout: std::time::Duration::from_millis(500),
        approval_timeout: std::time::Duration::from_millis(500),
        ..ClientConfig::default()
    }
}

pub fn detail(
    s: &str,
) -> tessera_protocol::bounded::BoundedString<{ tessera_protocol::MAX_DETAIL }> {
    tessera_protocol::bounded::BoundedString::new(s).unwrap()
}
