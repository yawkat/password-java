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
  stateDirectory = lib.removeSuffix "/" (lib.removePrefix stateDirPrefix cfg.dataDir);
  useStateDirectory = lib.hasPrefix stateDirPrefix cfg.dataDir && stateDirectory != "";
  # ProtectHome=true makes these inaccessible to the service
  homeDirs = [
    "/home"
    "/root"
    "/run/user"
  ];
  isBelow = parent: path: path == parent || lib.hasPrefix "${parent}/" path;
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
      type = lib.types.str;
      default = "/var/lib/password";
      description = ''
        Directory holding the shared secret and the encrypted database. Must be an absolute path
        without whitespace or `%`. If it is below `/var/lib`, it is managed through systemd's
        `StateDirectory`; otherwise it is created by systemd-tmpfiles. It cannot be below `/home`,
        `/root` or `/run/user`, because the service runs with `ProtectHome`.
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
    assertions = [
      {
        # dataDir is interpolated unquoted into ExecStart, WorkingDirectory, ReadWritePaths and tmpfiles
        assertion = builtins.match "/[^[:space:]%]*" cfg.dataDir != null;
        message = "services.password-server.dataDir must be an absolute path without whitespace or '%'.";
      }
      {
        assertion = !lib.any (d: isBelow d cfg.dataDir) homeDirs;
        message = "services.password-server.dataDir cannot be below ${lib.concatStringsSep ", " homeDirs} because the service uses ProtectHome.";
      }
    ];

    users.users = lib.mkIf (cfg.user == "password") {
      password = {
        isSystemUser = true;
        inherit (cfg) group;
        home = cfg.dataDir;
      };
    };

    users.groups = lib.mkIf (cfg.group == "password") { password = { }; };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    systemd.tmpfiles.rules = lib.mkIf (!useStateDirectory) [
      "d ${cfg.dataDir} 0700 ${cfg.user} ${cfg.group} -"
    ];

    systemd.services.password-server = {
      description = "password-java database server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} -p ${toString cfg.port} -d ${cfg.dataDir}";
        WorkingDirectory = cfg.dataDir;
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";
        # the JVM exits with 128+SIGTERM on a normal stop
        SuccessExitStatus = "143";

        # hardening: the server only needs to listen on a port and write to dataDir
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
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
      // (
        if useStateDirectory then
          {
            StateDirectory = stateDirectory;
            StateDirectoryMode = "0700";
          }
        else
          {
            # StateDirectory is writable implicitly; other locations need an explicit exception
            ReadWritePaths = [ cfg.dataDir ];
          }
      );
    };
  };
}
