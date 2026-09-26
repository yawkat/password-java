{
  lib,
  runCommand,
  makeWrapper,
  jdk25_headless,
  password-jars,
}:

runCommand "password-server-${password-jars.version}"
  {
    nativeBuildInputs = [ makeWrapper ];
    passthru = {
      inherit password-jars;
      # lets `nix build .#server.mitmCache.updateScript` regenerate deps.json
      inherit (password-jars) mitmCache;
    };
    meta = password-jars.meta // {
      description = "Server of the password-java password manager";
      mainProgram = "password-server";
    };
  }
  ''
    makeWrapper ${lib.getExe jdk25_headless} $out/bin/password-server \
      --add-flags "-jar ${password-jars}/share/password/server.jar"
  ''
