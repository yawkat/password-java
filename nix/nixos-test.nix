# Boots VMs running the NixOS module and exercises the server protocol the way the client does.
{ self, testers }:

let
  common =
    { pkgs, ... }:
    {
      imports = [ self.nixosModules.default ];
      environment.systemPackages = [ pkgs.curl ];
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

    def check_server(m, data_dir):
        m.wait_for_unit("password-server.service")
        m.wait_for_open_port(8081)
        # logs go through logback to the journal
        m.wait_until_succeeds("journalctl -u password-server.service | grep -q 'Startup completed'")

        # no shared secret yet
        assert status(m, f"{url}/challenge") == "404"

        m.succeed("head -c 32 /dev/urandom > /tmp/secret")
        m.succeed(f"curl -sf -X PUT --data-binary @/tmp/secret {url}/shared-secret")

        # the secret can only be set once
        assert_denied(m, f"-X PUT --data-binary other {url}/shared-secret")
        m.succeed(f"cmp /tmp/secret {data_dir}/shared-secret")

        # authenticated round trip, token = lowercase hex of sha512(secret || challenge), as in DatabaseClient
        def token():
            m.succeed(f"curl -sf -o /tmp/challenge {url}/challenge")
            m.succeed("test \"$(stat -c %s /tmp/challenge)\" = 32")
            return m.succeed("cat /tmp/secret /tmp/challenge | sha512sum | cut -d' ' -f1").strip()

        m.succeed("head -c 1000 /dev/urandom > /tmp/db")
        m.succeed(f"curl -sf -X PUT -H 'X-Auth-Token: {token()}' --data-binary @/tmp/db {url}/db")
        m.succeed(f"curl -sf -H 'X-Auth-Token: {token()}' -o /tmp/db-read {url}/db")
        m.succeed("cmp /tmp/db /tmp/db-read")
        # unauthenticated database access is refused
        assert_denied(m, f"{url}/db")
        assert_denied(m, f"-X PUT --data-binary other {url}/db")
        # tokens are single use
        t = token()
        m.succeed(f"curl -sf -H 'X-Auth-Token: {t}' -o /dev/null {url}/db")
        assert_denied(m, f"-H 'X-Auth-Token: {t}' {url}/db")

        # state lives in dataDir: a timestamped copy plus the `latest` link
        m.succeed(f"test -L {data_dir}/latest")
        m.succeed(f"cmp /tmp/db {data_dir}/latest")
        m.succeed(f"find {data_dir} -maxdepth 1 -type f -name '????-??-??T*Z' | grep -q .")
        m.succeed(f"test \"$(stat -c '%U %a' {data_dir})\" = 'password 700'")

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
