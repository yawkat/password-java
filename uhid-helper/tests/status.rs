//! Runs the helper with the client on stdin and stdout, without /dev/uhid.

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

/// Run the helper on `device`: the status byte it sends (if any), and its exit code
fn run(device: &str) -> (Option<u8>, i32) {
    let (mut app, helper) = UnixStream::pair().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_password-uhid"))
        .arg(device)
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(helper.try_clone().unwrap())))
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(helper)))
        .spawn()
        .unwrap();
    let mut status = [0];
    let status = app.read_exact(&mut status).ok().map(|()| status[0]);
    let code = child.wait().unwrap().code().unwrap();
    (status, code)
}

#[test]
fn missing_device() {
    // ENOENT
    assert_eq!(run("/nonexistent/uhid"), (Some(2), 1));
}

#[test]
fn device_closes() {
    // /dev/null takes the creation, then reads as end of file, which ends the relay
    assert_eq!(run("/dev/null"), (Some(0), 1));
}

#[test]
fn usage() {
    let status = Command::new(env!("CARGO_BIN_EXE_password-uhid")).args(["a", "b"]).status().unwrap();
    assert_eq!(status.code(), Some(2));
}
