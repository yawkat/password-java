{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.password-server;
  stateDirPrefix = "/var/lib/";
  useStateDirectory = lib.hasPrefix stateDirPrefix cfg.dataDir;
in
{
  options.services.password-server = {
    enable = lib.mkEnableOption "the password-java database server";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.server;
      defaultText = lib.literalExpression "password-java.packages.\${system}.server";
      description = "The password server package to use.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "TCP port the server listens on (all interfaces).";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/password";
      description = ''
        Directory holding the shared secret and the encrypted database. If it is below
        `/var/lib`, it is created and managed through systemd's `StateDirectory`.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "password";
      description = "User the server runs as. Created automatically if left at the default.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "password";
      description = "Group the server runs as. Created automatically if left at the default.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open {option}`services.password-server.port` in the firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users = lib.mkIf (cfg.user == "password") {
      password = {
        isSystemUser = true;
        inherit (cfg) group;
        home = cfg.dataDir;
      };
    };

    users.groups = lib.mkIf (cfg.group == "password") { password = { }; };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    systemd.services.password-server = {
      description = "password-java database server";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} -p ${toString cfg.port} -d ${lib.escapeShellArg cfg.dataDir}";
        WorkingDirectory = cfg.dataDir;
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";

        # hardening: the server only needs to listen on a port and write to dataDir
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ cfg.dataDir ];
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        CapabilityBoundingSet = if cfg.port < 1024 then [ "CAP_NET_BIND_SERVICE" ] else "";
        AmbientCapabilities = lib.optional (cfg.port < 1024) "CAP_NET_BIND_SERVICE";
      }
      // lib.optionalAttrs useStateDirectory {
        StateDirectory = lib.removePrefix stateDirPrefix cfg.dataDir;
        StateDirectoryMode = "0700";
      };
    };
  };
}
