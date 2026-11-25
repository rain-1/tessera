//! CLI tests: argument parsing, and the real `tessera` binary run with a
//! mock broker on fd 3 (exercising `Client::from_env`).

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;

use command_fds::{CommandFdExt, FdMapping};
use tessera_cli::{Command as Cmd, Source, parse};
use tessera_protocol::bounded::{BoundedBytes, BoundedString};
use tessera_protocol::unix::{recv_packet, send_packet, seqpacket_pair};
use tessera_protocol::{
    ClientMessage, ErrorCode, FrameLimits, Request, Response, ServerMessage, WireBudget, WireDepth,
    WireExpiry, WireFileRights, WireOperation, WireOperationResult, WireScope, decode_client,
    encode_server,
};

fn args(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}

#[test]
fn parses_request_with_scope_and_terms() {
    let inv = parse(&args(
        "--json --timeout 5s request --https 7 --methods get,post --max-body 1024 \
         --budget 100 --depth 2 --expiry 5m --request-id 0xab",
    ))
    .unwrap();
    assert!(inv.json);
    assert_eq!(inv.timeout, Some(std::time::Duration::from_secs(5)));
    match inv.command {
        Cmd::Request {
            terms, request_id, ..
        } => {
            assert_eq!(request_id, Some(0xab));
            assert_eq!(terms.budget, WireBudget::Finite(100));
            assert_eq!(terms.depth, WireDepth::Finite(2));
            assert_eq!(terms.expiry, WireExpiry::WithinMillis(300_000));
            match terms.scope {
                WireScope::Https {
                    endpoint_id: 7,
                    methods,
                    max_body_bytes: 1024,
                } => assert!(methods.get && methods.post && !methods.put),
                other => panic!("{other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn parses_other_commands() {
    assert!(matches!(
        parse(&args("replace --cap 1 --stdin")).unwrap().command,
        Cmd::Replace {
            cap: 1,
            source: Source::Stdin,
            ..
        }
    ));
    match parse(&args(
        "delegate --cap ff --to 1:2 --file 3 --rights read,replace --budget 1",
    ))
    .unwrap()
    .command
    {
        Cmd::Delegate { cap, to, terms, .. } => {
            assert_eq!(cap, 0xff);
            assert_eq!(to.to_string(), format!("{:032x}:2", 1));
            assert_eq!(
                terms.scope,
                WireScope::File {
                    object_id: 3,
                    rights: WireFileRights {
                        read_snapshot: true,
                        replace_content: true
                    }
                }
            );
        }
        other => panic!("{other:?}"),
    }
    match parse(&[
        "http".into(),
        "--cap".into(),
        "a".into(),
        "-H".into(),
        "Accept: text/plain".into(),
        "--method".into(),
        "post".into(),
        "--data".into(),
        "x=1".into(),
    ])
    .unwrap()
    .command
    {
        Cmd::Http { headers, body, .. } => {
            assert_eq!(headers, vec![("Accept".into(), b"text/plain".to_vec())]);
            assert_eq!(body, Some(Source::Inline(b"x=1".to_vec())));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn rejects_bad_usage() {
    for bad in [
        "",
        "frobnicate",
        "read",
        "read --cap zz",
        "read --cap 1 --cap 2",
        "request --budget 1",
        "request --file 1 --https 2 --budget 1",
        "replace --cap 1",
        "inspect --cap 1 --bogus 3",
        "delegate --cap 1 --to nobody --file 1 --budget 1",
    ] {
        assert!(parse(&args(bad)).is_err(), "{bad:?} should be rejected");
    }
}

/// Run the real binary with a mock broker on fd 3.
fn run_cli(
    cli_args: &str,
    stdin: &[u8],
    reply: impl FnOnce(&ClientMessage) -> Response + Send + 'static,
) -> (i32, String, String, Option<ClientMessage>) {
    run_cli_multi(cli_args, stdin, std::time::Duration::ZERO, move |m| {
        vec![reply(m)]
    })
}

/// Like [`run_cli`], answering the first request with several responses
/// (e.g. an interim `GrantPending` and then the final answer).
fn run_cli_multi(
    cli_args: &str,
    stdin: &[u8],
    hold_open: std::time::Duration,
    reply: impl FnOnce(&ClientMessage) -> Vec<Response> + Send + 'static,
) -> (i32, String, String, Option<ClientMessage>) {
    let (client_fd, server_fd) = seqpacket_pair().unwrap();
    let broker = thread::spawn(move || {
        let p = recv_packet(&server_fd, FrameLimits::default()).ok()??;
        let msg = decode_client(&p, 1 << 20).unwrap();
        for response in reply(&msg) {
            let resp = encode_server(&ServerMessage {
                correlation_id: msg.correlation_id,
                response,
            })
            .unwrap();
            send_packet(&server_fd, &resp, FrameLimits::default()).unwrap();
        }
        thread::sleep(hold_open);
        Some(msg)
    });
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tessera"));
    cmd.args(args(cli_args))
        .env("TESSERA_BROKER_FD", "3")
        .env("TESSERA_AGENT_ID", "worker-label")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.fd_mappings(vec![FdMapping {
        parent_fd: client_fd,
        child_fd: 3,
    }])
    .unwrap();
    let mut child = cmd.spawn().unwrap();
    drop(cmd); // closes our copy of the client end
    {
        use std::io::Write;
        let mut si = child.stdin.take().unwrap();
        si.write_all(stdin).unwrap();
    }
    let mut out = String::new();
    let mut err = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    let status = child.wait().unwrap();
    let msg = broker.join().unwrap();
    (status.code().unwrap(), out, err, msg)
}

#[test]
fn binary_inspect_json_via_env_fd() {
    let (code, out, _err, msg) = run_cli("--json inspect --cap 2a", b"", |m| match m.request {
        Request::Inspect { cap_id } => Response::Inspected(tessera_protocol::WireCapabilityView {
            cap_id,
            root_id: 1,
            parent: None,
            owner: tessera_protocol::WireAgentId {
                epoch: 9,
                serial: 4,
            },
            scope: WireScope::File {
                object_id: 3,
                rights: WireFileRights {
                    read_snapshot: true,
                    replace_content: false,
                },
            },
            budget_remaining: WireBudget::Finite(1),
            depth: WireDepth::Finite(0),
            expires_in_millis: Some(300_000),
            status: tessera_protocol::WireCapStatus::Live,
        }),
        _ => panic!(),
    });
    assert_eq!(code, 0, "{out}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["cap_id"], format!("{:032x}", 0x2a));
    assert_eq!(v["budget_remaining"], 1);
    assert_eq!(v["status"], "live");
    assert_eq!(msg.unwrap().request, Request::Inspect { cap_id: 0x2a });
}

#[test]
fn binary_replace_from_stdin_and_never_sends_label() {
    let (code, out, _err, msg) = run_cli(
        "replace --cap 5 --stdin --request-id 77",
        b"new content",
        |m| Response::Consumed {
            request_id: m.request.request_id().unwrap(),
            reservation_id: 1,
            result: WireOperationResult::FileReplaced { bytes_written: 11 },
        },
    );
    assert_eq!(code, 0);
    assert!(out.contains("11 bytes written"), "{out}");
    let msg = msg.unwrap();
    assert_eq!(
        msg.request,
        Request::Consume {
            request_id: 0x77,
            cap_id: 5,
            operation: WireOperation::FileReplaceContent {
                bytes: BoundedBytes::new(b"new content".to_vec()).unwrap()
            }
        }
    );
    let raw = tessera_protocol::encode_client(&msg).unwrap();
    assert!(!raw.windows(12).any(|w| w == b"worker-label"));
}

#[test]
fn binary_read_writes_raw_bytes_to_stdout() {
    let (code, out, _err, _) =
        run_cli("read --cap 5 --max-bytes 10", b"", |m| Response::Consumed {
            request_id: m.request.request_id().unwrap(),
            reservation_id: 1,
            result: WireOperationResult::FileSnapshot {
                bytes: BoundedBytes::new(b"secret".to_vec()).unwrap(),
                truncated: false,
            },
        });
    assert_eq!((code, out.as_str()), (0, "secret"));
}

#[test]
fn binary_denial_exit_code_and_json_error() {
    let (code, out, err, _) = run_cli("--json drop --cap 5", b"", |m| Response::Error {
        request_id: m.request.request_id(),
        code: ErrorCode::UnknownCapability,
        detail: BoundedString::new("no such capability").unwrap(),
    });
    assert_eq!(code, 1);
    assert!(err.contains("UnknownCapability"), "{err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["error"]["code"], "UnknownCapability");
}

#[test]
fn binary_request_sends_description_and_reports_pending() {
    let (code, out, err, msg) = run_cli_multi(
        "request --file 3 --budget 1 --description please",
        b"",
        std::time::Duration::ZERO,
        |m| {
            let request_id = m.request.request_id().unwrap();
            vec![
                Response::GrantPending {
                    request_id,
                    expires_in_millis: 120_000,
                },
                Response::GrantIssued {
                    request_id,
                    cap_id: 0xbeef,
                },
            ]
        },
    );
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("waiting for operator approval"), "{err}");
    assert!(err.contains("expires in 120s"), "{err}");
    assert!(out.contains(&format!("{:032x}", 0xbeef)));
    match msg.unwrap().request {
        Request::RequestGrant {
            untrusted_description,
            ..
        } => assert_eq!(untrusted_description.unwrap().as_str(), "please"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn binary_request_pending_then_client_timeout_is_uncertain() {
    // Acknowledged (GrantPending) but no decision before the approval
    // timeout: exit 3 with the id to repeat, not a "broker hung" timeout.
    let (code, out, err, _) = run_cli_multi(
        "--json --approval-timeout 300ms request --file 3 --budget 1",
        b"",
        std::time::Duration::from_secs(2),
        |m| {
            vec![Response::GrantPending {
                request_id: m.request.request_id().unwrap(),
                expires_in_millis: 60_000,
            }]
        },
    );
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("still waiting for the operator"), "{err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["error"]["outcome_uncertain"], true);
}

#[test]
fn binary_list_capabilities() {
    let (code, out, err, msg) = run_cli("--json list", b"", |_| Response::Capabilities {
        caps: tessera_protocol::bounded::BoundedVec::new(vec![
            tessera_protocol::WireCapabilityView {
                cap_id: 0x77,
                root_id: 0x70,
                parent: Some(0x71),
                owner: tessera_protocol::WireAgentId {
                    epoch: 1,
                    serial: 2,
                },
                scope: WireScope::File {
                    object_id: 3,
                    rights: WireFileRights {
                        read_snapshot: true,
                        replace_content: false,
                    },
                },
                budget_remaining: WireBudget::Finite(2),
                depth: WireDepth::Finite(0),
                expires_in_millis: None,
                status: tessera_protocol::WireCapStatus::Live,
            },
        ])
        .unwrap(),
        more: false,
    });
    assert_eq!(code, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["caps"][0]["cap_id"], format!("{:032x}", 0x77));
    assert!(matches!(
        msg.unwrap().request,
        Request::ListCapabilities { after: None }
    ));
}

#[test]
fn binary_without_broker_fd_fails_cleanly() {
    let out = Command::new(env!("CARGO_BIN_EXE_tessera"))
        .args(["inspect", "--cap", "1"])
        .env_remove("TESSERA_BROKER_FD")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&out.stderr).contains("TESSERA_BROKER_FD"));
}

#[test]
fn binary_refuses_non_socket_fd() {
    let out = Command::new(env!("CARGO_BIN_EXE_tessera"))
        .args(["inspect", "--cap", "1"])
        .env("TESSERA_BROKER_FD", "0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
}
