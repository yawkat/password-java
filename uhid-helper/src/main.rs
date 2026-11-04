//! password-uhid: creates the virtual FIDO security key of the password-java desktop app on its behalf, so the app
//! doesn't need access to `/dev/uhid`. Whoever can open `/dev/uhid` can create any HID device, a keyboard for
//! instance; through this helper, a client can only create this one device and answer for it.
//!
//! The client's connection is on stdin and stdout, e.g. from a systemd socket with `Accept=yes` (see
//! `password-uhid.socket`). The helper never hands out its `/dev/uhid` file: after `UHID_DESTROY` the kernel accepts
//! another `UHID_CREATE2` on the same file, so it relays events instead.
//!
//! Protocol, on a stream socket:
//!  1. The helper opens `/dev/uhid` and creates the device. It writes one byte, 0 if that worked, otherwise the
//!     errno, and in that case closes the connection.
//!  2. From then on, both directions carry whole `struct uhid_event` (`linux/uhid.h`, 4380 bytes in the machine's
//!     byte order). The kernel's events are passed to the client as they are. Of the client's events, `UHID_INPUT2`,
//!     `UHID_GET_REPORT_REPLY` and `UHID_SET_REPORT_REPLY` are passed to the kernel; `UHID_DESTROY`, end of file or
//!     anything else closes the connection, and with it `/dev/uhid`, which removes the device.
//!
//! Usage: `password-uhid [DEVICE]`, DEVICE defaults to `/dev/uhid`.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};
use std::thread;

const DEVICE_NAME: &str = "password-java security key";

/// FIDO usage page (0xF1D0), CTAPHID usage, 64 bytes of input (usage 0x20) and output (usage 0x21). Browsers, and
/// systemd's `fido_id` (which gives the hidraw device to the user at the seat), recognize a security key by it. The
/// same as `Uhid.FIDO_REPORT_DESCRIPTOR` of the app.
const FIDO_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAPHID)
    0xa1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xc0, // End Collection
];

// enum uhid_event_type
const UHID_DESTROY: u32 = 1;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT_REPLY: u32 = 14;

const BUS_USB: u16 = 3;
const EIO: u8 = 5;

/// sizeof(struct uhid_event): the type and the union, whose largest member is `uhid_create2_req` (4372 bytes),
/// padded to the 8-byte alignment of the legacy `uhid_create_req`
const EVENT_SIZE: usize = 4380;

type Event = [u8; EVENT_SIZE];

fn event_type(event: &Event) -> u32 {
    u32::from_ne_bytes([event[0], event[1], event[2], event[3]])
}

/// The `UHID_CREATE2` event of the security key
fn create_event() -> Box<Event> {
    let mut event = Box::new([0; EVENT_SIZE]);
    event[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());
    let request = &mut event[4..];
    // name[128], NUL-terminated by the zeros after it; phys[64] and uniq[64] stay empty
    request[..DEVICE_NAME.len()].copy_from_slice(DEVICE_NAME.as_bytes());
    request[256..258].copy_from_slice(&(FIDO_REPORT_DESCRIPTOR.len() as u16).to_ne_bytes());
    request[258..260].copy_from_slice(&BUS_USB.to_ne_bytes());
    // vendor, product, version and country stay 0, then rd_data
    request[276..276 + FIDO_REPORT_DESCRIPTOR.len()].copy_from_slice(&FIDO_REPORT_DESCRIPTOR);
    event
}

/// Whether an event from the client may go to the kernel: the answers of a device, nothing that (re)creates one
fn client_event_allowed(event_type: u32) -> bool {
    matches!(event_type, UHID_INPUT2 | UHID_GET_REPORT_REPLY | UHID_SET_REPORT_REPLY)
}

/// Read a whole event: `false` at end of file before its first byte, an error at end of file within it
fn read_event(from: &mut impl Read, event: &mut Event) -> io::Result<bool> {
    let mut done = 0;
    while done < EVENT_SIZE {
        match from.read(&mut event[done..]) {
            Ok(0) if done == 0 => return Ok(false),
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short read from client")),
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Pass the client's events to the device until the client ends (`Ok`) or sends one that isn't allowed (`Err`)
fn client_to_device(mut client: impl Read, mut device: impl Write) -> io::Result<()> {
    let mut event = Box::new([0; EVENT_SIZE]);
    while read_event(&mut client, &mut event)? {
        match event_type(&event) {
            UHID_DESTROY => return Ok(()),
            t if client_event_allowed(t) => {
                // The kernel rejects some events depending on the device's state (e.g. input after UHID_STOP), as it
                // would for the app with direct access. That leaves the device as it was, so it isn't fatal.
                if let Err(e) = device.write_all(&event[..]) {
                    eprintln!("write to uhid: {e}");
                }
            }
            t => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("refused event {t} from client")));
            }
        }
    }
    Ok(())
}

/// Pass the device's events to the client until either fails
fn device_to_client(mut device: impl Read, mut client: impl Write) -> io::Result<()> {
    let mut event = Box::new([0; EVENT_SIZE]);
    loop {
        event.fill(0);
        // the kernel returns one whole event per read
        match device.read(&mut event[..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "uhid closed")),
            Ok(_) => client.write_all(&event[..])?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn open_device(path: &Path) -> io::Result<File> {
    let mut device = OpenOptions::new().read(true).write(true).open(path)?;
    device.write_all(&create_event()[..])?;
    Ok(device)
}

fn run(path: PathBuf) -> io::Result<()> {
    // unbuffered handles of the connection
    let mut client_out = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    let client_in = File::from(io::stdin().as_fd().try_clone_to_owned()?);

    let device = open_device(&path);
    let status = match &device {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            e.raw_os_error().and_then(|errno| u8::try_from(errno).ok()).filter(|&errno| errno != 0).unwrap_or(EIO)
        }
    };
    client_out.write_all(&[status])?;
    let device = match device {
        Ok(device) => device,
        Err(_) => process::exit(1),
    };

    let device_in = device.try_clone()?;
    thread::spawn(move || {
        if let Err(e) = device_to_client(device_in, client_out) {
            eprintln!("{e}");
        }
        process::exit(1);
    });
    client_to_device(client_in, device)
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().map_or_else(|| PathBuf::from("/dev/uhid"), PathBuf::from);
    if args.next().is_some() {
        eprintln!("usage: password-uhid [DEVICE]");
        return ExitCode::from(2);
    }
    // returning closes /dev/uhid, which removes the device
    match run(path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn event(event_type: u32, fill: u8) -> Vec<u8> {
        let mut event = vec![fill; EVENT_SIZE];
        event[0..4].copy_from_slice(&event_type.to_ne_bytes());
        event
    }

    /// Returns at most `chunk` bytes per read, like a socket might
    struct Chunked<R>(R, usize);

    impl<R: Read> Read for Chunked<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = buf.len().min(self.1);
            self.0.read(&mut buf[..len])
        }
    }

    #[test]
    fn create() {
        let event = create_event();
        assert_eq!(event_type(&event), UHID_CREATE2);
        let request = &event[4..];
        assert_eq!(&request[..DEVICE_NAME.len() + 1], b"password-java security key\0");
        assert!(request[128..256].iter().all(|&b| b == 0), "phys and uniq");
        assert_eq!(request[256..258], 34u16.to_ne_bytes());
        assert_eq!(request[258..260], 3u16.to_ne_bytes());
        assert!(request[260..276].iter().all(|&b| b == 0), "vendor, product, version and country");
        assert_eq!(request[276..281], [0x06, 0xd0, 0xf1, 0x09, 0x01]);
        assert_eq!(request[276 + 33], 0xc0);
        assert!(request[276 + 34..].iter().all(|&b| b == 0));
        // 4 + sizeof(struct uhid_create2_req), then padding
        assert_eq!(4 + 276 + 4096 + 4, EVENT_SIZE);
    }

    #[test]
    fn allowed() {
        for t in 0..256 {
            assert_eq!(client_event_allowed(t), t == 10 || t == 12 || t == 14, "event {t}");
        }
        assert!(!client_event_allowed(UHID_CREATE2));
        assert!(!client_event_allowed(0x1234_0000 | UHID_INPUT2));
    }

    #[test]
    fn answers_are_passed() {
        let sent = [event(UHID_INPUT2, 0xab), event(UHID_GET_REPORT_REPLY, 0), event(UHID_SET_REPORT_REPLY, 1)].concat();
        let mut device = Vec::new();
        client_to_device(Chunked(Cursor::new(&sent), 100), &mut device).unwrap();
        assert_eq!(device, sent);
    }

    #[test]
    fn destroy_ends() {
        // not passed on: closing /dev/uhid removes the device, and then nothing can create another one
        let sent = [event(UHID_INPUT2, 0), event(UHID_DESTROY, 0), event(UHID_INPUT2, 1)].concat();
        let mut device = Vec::new();
        client_to_device(Cursor::new(&sent), &mut device).unwrap();
        assert_eq!(device, event(UHID_INPUT2, 0));
    }

    #[test]
    fn others_are_refused() {
        // UHID_CREATE, UHID_OUTPUT, UHID_INPUT, UHID_CREATE2 and nonsense
        for t in [0, 6, 8, UHID_CREATE2, 0x1234_5678] {
            let sent = [event(UHID_INPUT2, 0), event(t, 0), event(UHID_INPUT2, 1)].concat();
            let mut device = Vec::new();
            let error = client_to_device(Cursor::new(&sent), &mut device).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(device, event(UHID_INPUT2, 0), "event {t}");
        }
    }

    #[test]
    fn short_event() {
        let sent = &event(UHID_INPUT2, 0)[..10];
        let mut device = Vec::new();
        let error = client_to_device(Cursor::new(sent), &mut device).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(device.is_empty());
    }

    /// Returns one event per read, like /dev/uhid
    struct Events(Vec<Vec<u8>>);

    impl Read for Events {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Ok(0);
            }
            let event = self.0.remove(0);
            buf[..event.len()].copy_from_slice(&event);
            Ok(event.len())
        }
    }

    #[test]
    fn kernel_events_are_passed() {
        // a shorter read is padded to a whole event
        let mut client = Vec::new();
        let error = device_to_client(Events(vec![event(6, 0xcd), event(2, 0)[..4].to_vec()]), &mut client).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let mut start = vec![0; EVENT_SIZE];
        start[0..4].copy_from_slice(&2u32.to_ne_bytes());
        assert_eq!(client, [event(6, 0xcd), start].concat());
    }
}
