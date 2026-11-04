# Boots a VM with the security key helper and talks to it the way the desktop app does, with the kernel's real uhid.
{
  self,
  testers,
  writeScriptBin,
  python3,
}:

let
  # uhid-client MODE: connects to the helper as the app would. MODE "e2e" also plays the browser through hidraw
  # (which needs root), "close" just creates the device and removes it again.
  uhid-client = writeScriptBin "uhid-client" ''
    #!${python3}/bin/python3
    import errno
    import fcntl
    import glob
    import os
    import socket
    import sys
    import time

    NAME = "password-java security key"


    def recv_exact(s, n):
        data = b""
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk:
                raise EOFError(f"closed after {len(data)} bytes")
            data += chunk
        return data


    def hidraw():
        found = []
        for uevent in glob.glob("/sys/class/hidraw/*/device/uevent"):
            try:
                with open(uevent) as f:
                    if f"HID_NAME={NAME}\n" in f.read():
                        found.append("/dev/" + uevent.split("/")[4])
            except OSError:
                # removed meanwhile
                pass
        return found


    def wait_for(condition):
        for _ in range(100):
            if condition():
                return
            time.sleep(0.1)
        raise TimeoutError()


    def feature_ioctl(nr, size):
        # _IOC(_IOC_READ | _IOC_WRITE, 'H', nr, size)
        return (3 << 30) | (size << 16) | (ord("H") << 8) | nr


    def assert_refused(fd, nr):
        start = time.monotonic()
        try:
            fcntl.ioctl(fd, feature_ioctl(nr, 65), bytearray(65))
            raise AssertionError("feature report request succeeded")
        except OSError as e:
            assert e.errno == errno.EIO, e
        # answered by the helper, not the kernel's 5 second timeout
        assert time.monotonic() - start < 4


    mode = sys.argv[1]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/run/password-uhid.sock")
    assert recv_exact(s, 1) == b"\0", "status"
    wait_for(lambda: len(hidraw()) == 1)
    device = hidraw()[0]
    print("device", device)

    if mode == "e2e":
        fd = os.open(device, os.O_RDWR)
        # an output report from the "browser": a 0 for the report number, then 64 bytes
        report = bytes(range(64))
        os.write(fd, b"\0" + report)
        assert recv_exact(s, 64) == report
        # one of the wrong size is dropped
        os.write(fd, b"\0" + bytes(10))
        os.write(fd, b"\0" + bytes(reversed(report)))
        assert recv_exact(s, 64) == bytes(reversed(report))
        # the answer: an input report
        answer = bytes([7] * 64)
        s.sendall(answer)
        assert os.read(fd, 64) == answer
        # feature reports (HIDIOCSFEATURE, HIDIOCGFEATURE) are refused
        assert_refused(fd, 6)
        assert_refused(fd, 7)
        os.close(fd)
    elif mode != "close":
        raise ValueError(mode)

    s.close()
    wait_for(lambda: not hidraw())
    print("device removed")
  '';
in
testers.runNixOSTest {
  name = "password-uhid";

  nodes.machine = {
    imports = [ self.nixosModules.default ];
    services.password-uhid = {
      enable = true;
      group = "fido";
    };
    environment.systemPackages = [ uhid-client ];
    users.users.alice = {
      isNormalUser = true;
      extraGroups = [ "fido" ];
    };
    # in "users", the default group of NixOS users, but not in "fido"
    users.users.bob.isNormalUser = true;
    users.groups.fido = { };
  };

  testScript = ''
    machine.wait_for_unit("password-uhid.socket")
    machine.succeed("test \"$(stat -c '%G %a' /run/password-uhid.sock)\" = 'fido 660'")
    # switching configurations leaves running instances alone
    machine.succeed("systemctl cat password-uhid@.service | grep -x X-RestartIfChanged=false")

    with subtest("relay through the kernel"):
        machine.succeed("uhid-client e2e >&2")

    with subtest("a member of the group can create the key"):
        machine.succeed("su alice -c 'uhid-client close' >&2")
        # the user still can't open /dev/uhid itself
        machine.fail("su alice -c 'test -w /dev/uhid'")

    with subtest("others can't"):
        out = machine.fail("su bob -c 'uhid-client close' 2>&1")
        assert "PermissionError" in out, out

    with subtest("no instances are left behind"):
        machine.wait_until_succeeds("! systemctl list-units --all --no-legend 'password-uhid@*' | grep -q .")
        machine.succeed("journalctl -u 'password-uhid@*' >&2")
  '';
}
