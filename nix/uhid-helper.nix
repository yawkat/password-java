# The privileged helper that creates the desktop app's virtual security key, see uhid-helper/src/main.rs.
{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "password-uhid";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../uhid-helper;
    fileset = lib.fileset.unions [
      ../uhid-helper/Cargo.toml
      ../uhid-helper/Cargo.lock
      ../uhid-helper/password-uhid.socket
      # not a valid path literal
      (../uhid-helper + "/password-uhid@.service")
      ../uhid-helper/src
      ../uhid-helper/tests
    ];
  };

  # no dependencies
  cargoLock.lockFile = ../uhid-helper/Cargo.lock;

  postInstall = ''
    install -Dm644 -t $out/lib/systemd/system password-uhid.socket password-uhid@.service
    substituteInPlace $out/lib/systemd/system/password-uhid@.service \
      --replace-fail /usr/local/bin/password-uhid $out/bin/password-uhid
  '';

  meta = {
    description = "Helper that creates the virtual FIDO security key of the password-java desktop app";
    homepage = "https://github.com/yawkat/password-java";
    mainProgram = "password-uhid";
    platforms = lib.platforms.linux;
  };
}
