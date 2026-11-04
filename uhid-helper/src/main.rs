//! password-uhid: creates the virtual FIDO security key of the password-java desktop app on its behalf, so the app
//! doesn't need access to `/dev/uhid`. Whoever can open `/dev/uhid` can create any HID device, a keyboard for
//! instance; through this helper, a client can only create this one device and exchange its reports.
//!
//! The client's connection is on stdin and stdout, e.g. from a systemd socket with `Accept=yes` (see
//! `password-uhid.socket`). The helper alone talks to `/dev/uhid`: every event it writes there is either the fixed
//! `UHID_CREATE2`, a refusal of the kernel's report requests, or an input report of exactly 64 bytes of the client's.
//!
//! Protocol, on a stream socket:
//!  1. The helper opens `/dev/uhid` and creates the device. It writes one byte, 0 if that worked, otherwise the
//!     errno, and in that case closes the connection.
//!  2. From then on, both directions carry CTAPHID reports of 64 bytes, without any framing: the client sends input
//!     reports (to the host) and receives output reports (from the host). The helper answers the host's other
//!     requests itself.
//!  3. When the client closes the connection, the helper exits, which removes the device.
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

/// The size of the reports in both directions
const REPORT_SIZE: usize = 64;

/// FIDO usage page (0xF1D0), CTAPHID usage, 64 bytes of input (usage 0x20) and output (usage 0x21), no report IDs.
/// Browsers, and systemd's `fido_id` (which gives the hidraw device to the user at the seat), recognize a security key
/// by it.
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

// enum uhid_event_type of linux/uhid.h
const UHID_OUTPUT: u32 = 6;
const UHID_GET_REPORT: u32 = 9;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT: u32 = 13;
const UHID_SET_REPORT_REPLY: u32 = 14;

const BUS_USB: u16 = 3;
const EIO: u8 = 5;

/// UHID_DATA_MAX
const DATA_MAX: usize = 4096;

/// sizeof(struct uhid_event): the type and the union, whose largest member is `uhid_create2_req` (4372 bytes),
/// padded to the 8-byte alignment of the legacy `uhid_create_req`
const EVENT_SIZE: usize = 4380;

type Event = [u8; EVENT_SIZE];

fn new_event(event_type: u32) -> Box<Event> {
    let mut event = Box::new([0; EVENT_SIZE]);
    event[0..4].copy_from_slice(&event_type.to_ne_bytes());
    event
}

fn u16_at(event: &Event, offset: usize) -> u16 {
    u16::from_ne_bytes([event[offset], event[offset + 1]])
}

fn u32_at(event: &Event, offset: usize) -> u32 {
    u32::from_ne_bytes([event[offset], event[offset + 1], event[offset + 2], event[offset + 3]])
}

/// The `UHID_CREATE2` event of the security key
fn create_event() -> Box<Event> {
    let mut event = new_event(UHID_CREATE2);
    let request = &mut event[4..];
    // name[128], NUL-terminated by the zeros after it; phys[64] and uniq[64] stay empty
    request[..DEVICE_NAME.len()].copy_from_slice(DEVICE_NAME.as_bytes());
    request[256..258].copy_from_slice(&(FIDO_REPORT_DESCRIPTOR.len() as u16).to_ne_bytes());
    request[258..260].copy_from_slice(&BUS_USB.to_ne_bytes());
    // vendor, product, version and country stay 0, then rd_data
    request[276..276 + FIDO_REPORT_DESCRIPTOR.len()].copy_from_slice(&FIDO_REPORT_DESCRIPTOR);
    event
}

/// A `UHID_INPUT2` event: `uhid_input2_req` is a u16 size and the data
fn input_event(report: &[u8; REPORT_SIZE]) -> Box<Event> {
    let mut event = new_event(UHID_INPUT2);
    event[4..6].copy_from_slice(&(REPORT_SIZE as u16).to_ne_bytes());
    event[6..6 + REPORT_SIZE].copy_from_slice(report);
    event
}

/// A reply to `UHID_GET_REPORT` or `UHID_SET_REPORT` with this id: we have no feature reports. Both replies start with
/// the id and a u16 err; the rest of `uhid_get_report_reply_req` (size and data) stays empty.
fn refusal(reply_type: u32, id: u32) -> Box<Event> {
    let mut reply = new_event(reply_type);
    reply[4..8].copy_from_slice(&id.to_ne_bytes());
    reply[8..10].copy_from_slice(&u16::from(EIO).to_ne_bytes());
    reply
}

/// What to do about an event of the kernel
#[derive(Debug, PartialEq)]
enum Action {
    /// Pass an output report from the host to the client
    Output([u8; REPORT_SIZE]),
    /// Write this reply to the kernel
    Reply(Box<Event>),
    /// Nothing: START, STOP, OPEN, CLOSE, and output reports of the wrong size or without the report number
    Ignore,
}

fn handle_kernel_event(event: &Event) -> Action {
    match u32_at(event, 0) {
        UHID_OUTPUT => {
            // uhid_output_req: data[UHID_DATA_MAX], u16 size, u8 rtype
            let size = usize::from(u16_at(event, 4 + DATA_MAX));
            let data = &event[4..4 + size.min(DATA_MAX)];
            // the descriptor has no report IDs, so hidraw puts a 0 for the report number in front
            let report = match data {
                [0, report @ ..] if report.len() == REPORT_SIZE => report,
                _ => return Action::Ignore,
            };
            Action::Output(report.try_into().unwrap())
        }
        // uhid_get_report_req and uhid_set_report_req start with the id
        UHID_GET_REPORT => Action::Reply(refusal(UHID_GET_REPORT_REPLY, u32_at(event, 4))),
        UHID_SET_REPORT => Action::Reply(refusal(UHID_SET_REPORT_REPLY, u32_at(event, 4))),
        _ => Action::Ignore,
    }
}

/// Write an event in one write: the kernel takes each write as an event of its own, and always all of it
fn write_event(mut device: impl Write, event: &Event) -> io::Result<()> {
    match device.write(event) {
        Ok(EVENT_SIZE) => Ok(()),
        Ok(n) => Err(io::Error::other(format!("short write to uhid: {n}"))),
        // The kernel rejects some events depending on the device's state (e.g. input after UHID_STOP). That leaves
        // the device as it was, so it isn't fatal.
        Err(e) => {
            eprintln!("write to uhid: {e}");
            Ok(())
        }
    }
}

/// Pass the client's input reports to the device until the client ends (`Ok`) or fails (`Err`)
fn client_to_device(mut client: impl Read, mut device: impl Write) -> io::Result<()> {
    let mut report = [0; REPORT_SIZE];
    loop {
        let mut done = 0;
        while done < REPORT_SIZE {
            match client.read(&mut report[done..]) {
                Ok(0) if done == 0 => return Ok(()),
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short report from client")),
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        write_event(&mut device, &input_event(&report))?;
    }
}

/// Pass the device's output reports to the client and answer its requests, until something fails
fn device_to_client(mut device: impl Read + Write, mut client: impl Write) -> io::Result<()> {
    let mut event = Box::new([0; EVENT_SIZE]);
    loop {
        event.fill(0);
        // the kernel returns one whole event per read
        match device.read(&mut event[..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "uhid closed")),
            Ok(_) => match handle_kernel_event(&event) {
                Action::Output(report) => client.write_all(&report)?,
                Action::Reply(reply) => write_event(&mut device, &reply)?,
                Action::Ignore => {}
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn open_device(path: &Path) -> io::Result<File> {
    let mut device = OpenOptions::new().read(true).write(true).open(path)?;
    let written = device.write(&create_event()[..])?;
    if written != EVENT_SIZE {
        return Err(io::Error::other(format!("short write to uhid: {written}")));
    }
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

    fn output_event(data: &[u8]) -> Box<Event> {
        let mut event = new_event(UHID_OUTPUT);
        event[4..4 + data.len()].copy_from_slice(data);
        event[4 + DATA_MAX..4 + DATA_MAX + 2].copy_from_slice(&(data.len() as u16).to_ne_bytes());
        event
    }

    fn request_event(event_type: u32, id: u32) -> Box<Event> {
        let mut event = new_event(event_type);
        event[4..8].copy_from_slice(&id.to_ne_bytes());
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

    /// Takes at most `limit` bytes per write
    struct ShortWrites(Vec<u8>, usize);

    impl Write for ShortWrites {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let len = buf.len().min(self.1);
            self.0.extend_from_slice(&buf[..len]);
            Ok(len)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A fake /dev/uhid: one event per read, and the written events
    struct Device {
        events: Vec<Box<Event>>,
        written: Vec<u8>,
    }

    impl Read for Device {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.events.is_empty() {
                return Ok(0);
            }
            let event = self.events.remove(0);
            buf[..EVENT_SIZE].copy_from_slice(&event[..]);
            Ok(EVENT_SIZE)
        }
    }

    impl Write for Device {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn create() {
        let event = create_event();
        assert_eq!(u32_at(&event, 0), UHID_CREATE2);
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
        assert_eq!(4 + 276 + DATA_MAX + 4, EVENT_SIZE);
    }

    #[test]
    fn input() {
        let event = input_event(&[7; REPORT_SIZE]);
        assert_eq!(u32_at(&event, 0), UHID_INPUT2);
        assert_eq!(u16_at(&event, 4), 64);
        assert_eq!(event[6..70], [7; 64]);
        assert!(event[70..].iter().all(|&b| b == 0));
    }

    #[test]
    fn client_reports_become_input() {
        let sent = [[1; REPORT_SIZE], [2; REPORT_SIZE]].concat();
        let mut device = Vec::new();
        client_to_device(Chunked(Cursor::new(&sent), 10), &mut device).unwrap();
        assert_eq!(device, [&input_event(&[1; 64])[..], &input_event(&[2; 64])[..]].concat());
    }

    #[test]
    fn short_report() {
        let mut device = Vec::new();
        let error = client_to_device(Cursor::new(&[0; 10]), &mut device).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(device.is_empty());
    }

    #[test]
    fn short_write_ends() {
        // the rest is never written as an event of its own
        let mut device = ShortWrites(Vec::new(), 100);
        client_to_device(Cursor::new(&[0; 2 * REPORT_SIZE]), &mut device).unwrap_err();
        assert_eq!(device.0, input_event(&[0; 64])[..100]);
    }

    #[test]
    fn output() {
        let report: [u8; 64] = std::array::from_fn(|i| i as u8 + 1);
        // with hidraw's report number in front
        assert_eq!(handle_kernel_event(&output_event(&[&[0], &report[..]].concat())), Action::Output(report));
        // anything else is ignored
        assert_eq!(handle_kernel_event(&output_event(&report)), Action::Ignore);
        assert_eq!(handle_kernel_event(&output_event(&[&[0], &report[..63]].concat())), Action::Ignore);
        assert_eq!(handle_kernel_event(&output_event(&[&[1], &report[..]].concat())), Action::Ignore);
        assert_eq!(handle_kernel_event(&output_event(&[0; 66])), Action::Ignore);
        // a size beyond the data isn't trusted
        let mut event = output_event(&[]);
        event[4 + DATA_MAX..4 + DATA_MAX + 2].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert_eq!(handle_kernel_event(&event), Action::Ignore);
    }

    #[test]
    fn requests_are_refused() {
        let Action::Reply(reply) = handle_kernel_event(&request_event(UHID_GET_REPORT, 0x1234)) else { panic!() };
        assert_eq!(u32_at(&reply, 0), UHID_GET_REPORT_REPLY);
        assert_eq!(u32_at(&reply, 4), 0x1234);
        assert_eq!(u16_at(&reply, 8), 5);
        assert!(reply[10..].iter().all(|&b| b == 0), "size and data");

        let Action::Reply(reply) = handle_kernel_event(&request_event(UHID_SET_REPORT, 0x5678)) else { panic!() };
        assert_eq!(u32_at(&reply, 0), UHID_SET_REPORT_REPLY);
        assert_eq!(u32_at(&reply, 4), 0x5678);
        assert_eq!(u16_at(&reply, 8), 5);
        assert!(reply[10..].iter().all(|&b| b == 0));
    }

    #[test]
    fn others_are_ignored() {
        // START, STOP, OPEN, CLOSE
        for t in [2, 3, 4, 5, 0x1234_5678] {
            assert_eq!(handle_kernel_event(&new_event(t)), Action::Ignore);
        }
    }

    #[test]
    fn kernel_events() {
        let mut output = [3; 65];
        output[0] = 0;
        let mut device = Device {
            events: vec![new_event(2), output_event(&output), request_event(UHID_GET_REPORT, 9), new_event(4)],
            written: Vec::new(),
        };
        let mut client = Vec::new();
        let error = device_to_client(&mut device, &mut client).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(client, [3; 64]);
        assert_eq!(device.written, refusal(UHID_GET_REPORT_REPLY, 9)[..]);
    }
}
