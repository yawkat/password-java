# Builds the project's jars with Gradle and runs the test suite.
#
# Dependencies are pinned in ./deps.json. After changing any Gradle dependency or plugin, regenerate it
# by running this from the repository root (new files must be `git add`ed first so the flake sees them):
#
#   nix build .#server.mitmCache.updateScript && ./result
{
  lib,
  stdenv,
  gradle_9,
  jdk25,
}:

let
  gradle = gradle_9.override { java = jdk25; };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "password-jars";
  version = "0-unstable";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../build.gradle.kts
      ../settings.gradle.kts
      ../gradle/libs.versions.toml
      ../shared
      ../client
      ../server
      ../gui
    ];
  };

  nativeBuildInputs = [ gradle ];

  mitmCache = gradle.fetchDeps {
    pkg = finalAttrs.finalPackage;
    data = ./deps.json;
  };

  gradleBuildTask = ":server:shadowJar";

  doCheck = true;
  gradleCheckTask = "check";

  installPhase = ''
    runHook preInstall
    install -Dm644 server/build/libs/server-all.jar $out/share/password/server.jar
    runHook postInstall
  '';

  meta = {
    description = "Jars of the password-java password manager";
    homepage = "https://github.com/yawkat/password-java";
    platforms = lib.platforms.linux;
    sourceProvenance = with lib.sourceTypes; [
      fromSource
      binaryBytecode # dependencies from the mitm cache
    ];
  };
})
