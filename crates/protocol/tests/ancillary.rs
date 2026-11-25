//! SCM_RIGHTS rejection. Kept in its own test binary with a single test
//! function because it counts open descriptors in this process.

use std::fs::File;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;

use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use tessera_protocol::frame::{FrameError, FrameLimits, read_frame};
use tessera_protocol::unix::{CheckedStream, recv_packet, send_packet, seqpacket_pair};

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn send_with_fds(sock: BorrowedFd<'_>, data: &[u8], fds: &[BorrowedFd<'_>]) {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut ctl = SendAncillaryBuffer::new(&mut space);
    assert!(ctl.push(SendAncillaryMessage::ScmRights(fds)));
    let n =
        rustix::net::sendmsg(sock, &[IoSlice::new(data)], &mut ctl, SendFlags::NOSIGNAL).unwrap();
    assert_eq!(n, data.len());
}

#[test]
fn scm_rights_rejected_and_closed() {
    let f1 = File::open("/dev/null").unwrap();
    let f2 = File::open("/dev/null").unwrap();

    // SEQPACKET.
    let (a, b) = seqpacket_pair().unwrap();
    let before = open_fds();
    send_with_fds(a.as_fd(), b"\x00\x01hello", &[f1.as_fd(), f2.as_fd()]);
    match recv_packet(&b, FrameLimits::default()) {
        Err(FrameError::AncillaryRejected) => {}
        other => panic!("expected rejection, got {other:?}"),
    }
    assert_eq!(open_fds(), before, "received descriptors leaked");
    // A clean packet afterwards is still received.
    send_packet(&a, b"\x00\x01ok", FrameLimits::default()).unwrap();
    assert_eq!(
        recv_packet(&b, FrameLimits::default()).unwrap().unwrap(),
        b"\x00\x01ok"
    );

    // STREAM via CheckedStream + read_frame.
    let (c, d) = UnixStream::pair().unwrap();
    let before = open_fds();
    send_with_fds(c.as_fd(), &[0, 0, 0, 2, 0, 1], &[f1.as_fd()]);
    let mut rd = CheckedStream::new(d.as_fd());
    match read_frame(&mut rd, FrameLimits::default()) {
        Err(FrameError::AncillaryRejected) => {}
        other => panic!("expected rejection, got {other:?}"),
    }
    assert_eq!(open_fds(), before, "received descriptors leaked");
}
