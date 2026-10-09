# Boots VMs running the NixOS module and exercises the server protocol the way the client does.
{
  self,
  testers,
  writeShellApplication,
  openssl,
  xxd,
}:

let
  # Prints the X-Auth header for a request: pw-auth METHOD PATH BODY_FILE [KEY_FILE], signed with KEY_FILE
  # (default /tmp/key.pem). See AuthProtocol.signingInput.
  pw-auth = writeShellApplication {
    name = "pw-auth";
    runtimeInputs = [
      openssl
      xxd
    ];
    text = ''
      ts=$(date +%s%3N)
      nonce=$(head -c 16 /dev/urandom | xxd -p)
      body_hash=$(sha256sum < "$3" | cut -d' ' -f1)
      printf 'at.yawk.password/v1/request\n%s\n%s\n%s\n%s\n%s\n' "$ts" "$nonce" "$1" "$2" "$body_hash" > /tmp/msg
      sig=$(openssl pkeyutl -sign -inkey "''${4:-/tmp/key.pem}" -rawin -in /tmp/msg | xxd -p -c 64)
      echo "$ts $nonce $sig"
    '';
  };

  common =
    { pkgs, ... }:
    {
      imports = [ self.nixosModules.default ];
      environment.systemPackages = [
        pkgs.curl
        openssl
        xxd
        pw-auth
      ];
      services.password-server = {
        enable = true;
        port = 8081;
      };
      virtualisation.memorySize = 1024;
    };
in
testers.runNixOSTest {
  name = "password-server";

  nodes = {
    # default dataDir, managed through StateDirectory
    machine = common;
    # dataDir outside /var/lib, created through tmpfiles
    custom = {
      imports = [ common ];
      services.password-server.dataDir = "/srv/password";
    };
  };

  testScript = ''
    url = "http://127.0.0.1:8081"

    def status(m, args):
        return m.succeed(f"curl -s -o /dev/null -w '%{{http_code}}' {args}").strip()

    def assert_denied(m, args):
        code = status(m, args)
        assert code == "403", f"expected request to be denied with 403, got status {code}"

    def auth(m, method, path, body_file="/dev/null", key="/tmp/key.pem"):
        return m.succeed(f"pw-auth {method} {path} {body_file} {key}").strip()

    def check_server(m, data_dir):
        m.wait_for_unit("password-server.service")
        m.wait_for_open_port(8081)
        # logs go through logback to the journal
        m.wait_until_succeeds("journalctl -u password-server.service | grep -q 'Startup completed'")

        # not registered yet
        assert status(m, f"{url}/salt") == "404"

        # registration: version 1, install salt, raw Ed25519 public key
        m.succeed("openssl genpkey -algorithm ed25519 -out /tmp/key.pem")
        m.succeed("head -c 32 /dev/urandom > /tmp/salt")
        m.succeed("{ printf '\\x01'; cat /tmp/salt; openssl pkey -in /tmp/key.pem -pubout -outform DER | tail -c 32; } > /tmp/reg")
        m.succeed(f"curl -sf -X PUT --data-binary @/tmp/reg {url}/register")

        # the registration can only be set once
        assert_denied(m, f"-X PUT --data-binary @/tmp/reg {url}/register")
        m.succeed(f"cmp /tmp/reg {data_dir}/verifier")
        m.succeed(f"curl -sf {url}/salt | cmp - <(head -c 33 /tmp/reg)")

        # signed round trip of a database with a valid header
        m.succeed("{ printf 'PWDB\\x01'; cat /tmp/salt; head -c 1000 /dev/urandom; } > /tmp/db")
        m.succeed(f"curl -sf -X PUT -H 'X-Auth: {auth(m, 'PUT', '/db', '/tmp/db')}' --data-binary @/tmp/db {url}/db")
        m.succeed(f"curl -sf -H 'X-Auth: {auth(m, 'GET', '/db')}' -o /tmp/db-read {url}/db")
        m.succeed("cmp /tmp/db /tmp/db-read")
        # unauthenticated database access is refused
        assert_denied(m, f"{url}/db")
        assert_denied(m, f"-X PUT --data-binary @/tmp/db {url}/db")
        # a signature for GET doesn't authorize a PUT
        assert_denied(m, f"-X PUT -H 'X-Auth: {auth(m, 'GET', '/db')}' --data-binary @/tmp/db {url}/db")
        # requests can't be replayed
        h = auth(m, "GET", "/db")
        m.succeed(f"curl -sf -H 'X-Auth: {h}' -o /dev/null {url}/db")
        assert_denied(m, f"-H 'X-Auth: {h}' {url}/db")

        # the 2FA vault: the same protocol below /totp, with its own registration and key, in dataDir/totp
        assert status(m, f"{url}/totp/salt") == "404"
        m.succeed("openssl genpkey -algorithm ed25519 -out /tmp/totp-key.pem")
        m.succeed("head -c 32 /dev/urandom > /tmp/totp-salt")
        m.succeed("{ printf '\\x01'; cat /tmp/totp-salt; openssl pkey -in /tmp/totp-key.pem -pubout -outform DER | tail -c 32; } > /tmp/totp-reg")
        m.succeed(f"curl -sf -X PUT --data-binary @/tmp/totp-reg {url}/totp/register")
        m.succeed(f"cmp /tmp/totp-reg {data_dir}/totp/verifier")
        m.succeed("{ printf 'PWDB\\x01'; cat /tmp/totp-salt; head -c 1000 /dev/urandom; } > /tmp/totp-db")
        h = auth(m, "PUT", "/totp/db", "/tmp/totp-db", "/tmp/totp-key.pem")
        m.succeed(f"curl -sf -X PUT -H 'X-Auth: {h}' --data-binary @/tmp/totp-db {url}/totp/db")
        h = auth(m, "GET", "/totp/db", key="/tmp/totp-key.pem")
        m.succeed(f"curl -sf -H 'X-Auth: {h}' {url}/totp/db | cmp /tmp/totp-db -")
        # the password vault's key doesn't open it, and its database is untouched
        assert_denied(m, f"-H 'X-Auth: {auth(m, 'GET', '/totp/db')}' {url}/totp/db")
        m.succeed(f"curl -sf -H 'X-Auth: {auth(m, 'GET', '/db')}' {url}/db | cmp /tmp/db -")
        m.succeed(f"test \"$(stat -c '%U %a' {data_dir}/totp)\" = 'password 700'")

        # state lives in dataDir: a timestamped copy plus the `latest` link
        m.succeed(f"test -L {data_dir}/latest")
        m.succeed(f"cmp /tmp/db {data_dir}/latest")
        m.succeed(f"find {data_dir} -maxdepth 1 -type f -name '????-??-??T*Z' | grep -q .")
        m.succeed(f"test \"$(stat -c '%U %a' {data_dir})\" = 'password 700'")
        m.succeed(f"test \"$(stat -c '%a' {data_dir}/verifier)\" = '600'")

        # a normal stop is not a failure
        m.succeed("systemctl stop password-server.service")
        m.fail("systemctl is-failed password-server.service")

    start_all()
    with subtest("default dataDir"):
        check_server(machine, "/var/lib/password")
    with subtest("custom dataDir"):
        check_server(custom, "/srv/password")
  '';
}
