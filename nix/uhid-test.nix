# Boots a VM with the security key helper and talks to it the way the desktop app does, with the kernel's real uhid.
{
  self,
  testers,
  writeScriptBin,
  python3,
}:

let
  # uhid-client MODE: connects to the helper as the app would. MODE "e2e" also plays the browser through hidraw
  # (which needs root), "destroy" just creates the device and removes it again.
  uhid-client = writeScriptBin "uhid-client" ''
    #!${python3}/bin/python3
    import glob
    import os
    import socket
    import struct
    import sys
    import time

    EVENT_SIZE = 4380
    UHID_START, UHID_OPEN, UHID_OUTPUT = 2, 4, 6
    UHID_DESTROY, UHID_CREATE2, UHID_INPUT2 = 1, 11, 12
    NAME = "password-java security key"


    def recv_exact(s, n):
        data = b""
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk:
                raise EOFError(f"closed after {len(data)} bytes")
            data += chunk
        return data


    def recv_event(s):
        event = recv_exact(s, EVENT_SIZE)
        return struct.unpack_from("=I", event)[0], event


    def wait_for_event(s, wanted):
        while True:
            t, event = recv_event(s)
            print("event", t)
            if t == wanted:
                return event


    def send_event(s, t, body=b""):
        s.sendall((struct.pack("=I", t) + body).ljust(EVENT_SIZE, b"\0"))


    def hidraw():
        found = []
        for uevent in glob.glob("/sys/class/hidraw/*/device/uevent"):
            with open(uevent) as f:
                if f"HID_NAME={NAME}\n" in f.read():
                    found.append("/dev/" + uevent.split("/")[4])
        return found


    def wait_for(condition):
        for _ in range(100):
            if condition():
                return
            time.sleep(0.1)
        raise TimeoutError()


    def closed(s):
        try:
            while True:
                t, _ = recv_event(s)
                print("event", t)
        except EOFError:
            pass


    mode = sys.argv[1]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/run/password-uhid.sock")
    assert recv_exact(s, 1) == b"\0", "status"
    wait_for_event(s, UHID_START)
    wait_for(lambda: len(hidraw()) == 1)
    device = hidraw()[0]
    print("device", device)

    if mode == "e2e":
        fd = os.open(device, os.O_RDWR)
        wait_for_event(s, UHID_OPEN)
        # an output report from the "browser": a 0 for the report number, then 64 bytes
        report = bytes(range(64))
        os.write(fd, b"\0" + report)
        event = wait_for_event(s, UHID_OUTPUT)
        size = struct.unpack_from("=H", event, 4 + 4096)[0]
        assert event[4:4 + size] == b"\0" + report, event[4:4 + size]
        # the answer: an input report
        answer = bytes(reversed(range(64)))
        send_event(s, UHID_INPUT2, struct.pack("=H", 64) + answer)
        assert os.read(fd, 64) == answer
        os.close(fd)
        # creating a device of our own is refused, and ends this one
        create = bytearray(EVENT_SIZE - 4)
        create[0:8] = b"keyboard"
        send_event(s, UHID_CREATE2, bytes(create))
        closed(s)
    elif mode == "destroy":
        send_event(s, UHID_DESTROY)
        closed(s)
    else:
        raise ValueError(mode)

    wait_for(lambda: not hidraw())
    print("device removed")
  '';
in
testers.runNixOSTest {
  name = "password-uhid";

  nodes.machine = {
    imports = [ self.nixosModules.default ];
    services.password-uhid.enable = true;
    environment.systemPackages = [ uhid-client ];
    users.users.alice.isNormalUser = true;
    users.users.bob = {
      isNormalUser = true;
      group = "bob";
    };
    users.groups.bob = { };
  };

  testScript = ''
    machine.wait_for_unit("password-uhid.socket")
    machine.succeed("test \"$(stat -c '%G %a' /run/password-uhid.sock)\" = 'users 660'")

    with subtest("relay through the kernel"):
        machine.succeed("uhid-client e2e >&2")

    with subtest("a member of the group can create the key"):
        machine.succeed("su alice -c 'uhid-client destroy' >&2")
        # the user still can't open /dev/uhid itself
        machine.fail("su alice -c 'test -w /dev/uhid'")

    with subtest("others can't"):
        out = machine.fail("su bob -c 'uhid-client destroy' 2>&1")
        assert "PermissionError" in out, out

    with subtest("no instances are left behind"):
        machine.wait_until_succeeds("! systemctl list-units --all --no-legend 'password-uhid@*' | grep -q .")
        machine.succeed("journalctl -u 'password-uhid@*' >&2")
  '';
}
