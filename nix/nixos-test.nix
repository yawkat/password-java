# Boots a VM running the NixOS module and exercises the basic server protocol.
{ self, testers }:

testers.runNixOSTest {
  name = "password-server";

  nodes.machine = { pkgs, ... }: {
    environment.systemPackages = [ pkgs.curl ];
    imports = [ self.nixosModules.default ];
    services.password-server = {
      enable = true;
      port = 8081;
    };
    virtualisation.memorySize = 1024;
  };

  testScript = ''
    machine.wait_for_unit("password-server.service")
    machine.wait_for_open_port(8081)

    # no shared secret yet
    machine.succeed("test \"$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/challenge)\" = 404")

    machine.succeed("head -c 32 /dev/urandom > /tmp/secret")
    machine.succeed("curl -sf -X PUT --data-binary @/tmp/secret http://127.0.0.1:8081/shared-secret")
    # the secret can only be set once
    machine.fail("curl -sf -X PUT --data-binary 'other' http://127.0.0.1:8081/shared-secret")
    machine.succeed("cmp /tmp/secret /var/lib/password/shared-secret")

    machine.succeed("curl -sf -o /tmp/challenge http://127.0.0.1:8081/challenge")
    machine.succeed("test \"$(stat -c %s /tmp/challenge)\" = 32")

    # state lives in dataDir with restrictive permissions
    machine.succeed("test \"$(stat -c '%U %a' /var/lib/password)\" = 'password 700'")
  '';
}
