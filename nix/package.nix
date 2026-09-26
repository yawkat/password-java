# Builds the project's jars (server and desktop app) with Gradle and runs the test suite.
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
  # The desktop app bundles skiko for the build platform (compose.desktop.currentOs), and deps.json only pins the
  # linux-x64 variant, so it is only built there.
  withApp ? stdenv.hostPlatform.system == "x86_64-linux",
}:

let
  gradle = gradle_9.override { java = jdk25; };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "password-jars";
  version = "0-unstable";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions (
      [
        ../build.gradle.kts
        ../settings.gradle.kts
        ../gradle/libs.versions.toml
        ../shared
        ../client
        ../server
      ]
      ++ lib.optional withApp ../app
    );
  };

  nativeBuildInputs = [ gradle ];

  mitmCache = gradle.fetchDeps {
    pkg = finalAttrs.finalPackage;
    data = ./deps.json;
  };

  passthru = { inherit gradle withApp; };

  gradleFlags = lib.optional (!withApp) "-Ppassword.app=false";

  # the server's application distribution (lib/*.jar and start scripts; Micronaut doesn't support fat jars well)
  # and the desktop app's uber jar
  gradleBuildTask =
    ":server:installDist" + lib.optionalString withApp " :app:packageUberJarForCurrentOS";

  doCheck = true;
  gradleCheckTask = "check";

  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/password
    cp -r server/build/install/server/lib $out/share/password/lib
    # the runtime classpath in Gradle's order, taken from the distribution's start script
    sed -n 's|^CLASSPATH=||p' server/build/install/server/bin/server \
      | sed "s|\$APP_HOME/lib/|$out/share/password/lib/|g" > $out/share/password/classpath
    test -s $out/share/password/classpath
  ''
  + lib.optionalString withApp ''
    install -Dm644 app/build/compose/jars/password-gui-linux-x64-*.jar $out/share/password/app.jar
  ''
  + ''
    runHook postInstall
  '';

  meta = {
    description = "Server and desktop app jars of the password-java password manager";
    homepage = "https://github.com/yawkat/password-java";
    platforms = lib.platforms.linux;
    sourceProvenance = with lib.sourceTypes; [
      fromSource
      binaryBytecode # dependencies from the mitm cache
    ];
  };
})
