# The helper that creates the desktop app's virtual security key, see uhid-helper/.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.password-uhid;
in
{
  options.services.password-uhid = {
    enable = lib.mkEnableOption ''
      the helper that creates the virtual security key of the password-java desktop app, so that its
      users don't need access to `/dev/uhid`. It listens on `/run/password-uhid.sock`
    '';

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.uhid-helper;
      defaultText = lib.literalExpression "password-java.packages.\${system}.uhid-helper";
      description = "The helper package to use.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "users";
      description = ''
        Group allowed to connect to the helper, and so to create the security key. Each connection
        creates one device, until it is closed.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    boot.kernelModules = [ "uhid" ];
    # the units come with the package (uhid-helper/password-uhid.socket and password-uhid@.service)
    systemd.packages = [ cfg.package ];
    systemd.sockets.password-uhid = {
      wantedBy = [ "sockets.target" ];
      socketConfig.SocketGroup = cfg.group;
    };
  };
}
