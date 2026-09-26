{
  lib,
  runCommand,
  makeWrapper,
  writeText,
  jdk25,
  libGL,
  fontconfig,
  freetype,
  libx11,
  libxext,
  libxrender,
  libxi,
  libxtst,
  libxrandr,
  libxkbcommon,
  password-jars,
}:

let
  # native libraries loaded at runtime by skiko (OpenGL rendering, fonts) and by AWT (X11/XWayland windowing)
  libraryPath = lib.makeLibraryPath [
    libGL
    fontconfig
    freetype
    libx11
    libxext
    libxrender
    libxi
    libxtst
    libxrandr
    libxkbcommon
  ];

  desktopItem = writeText "at.yawk.password.desktop" ''
    [Desktop Entry]
    Type=Application
    Name=Passwords
    Comment=Password manager
    Exec=password-gui
    Icon=dialog-password
    Terminal=false
    Categories=Utility;Security;
    StartupWMClass=at-yawk-password-app-MainKt
  '';
in
runCommand "password-gui-${password-jars.version}"
  {
    nativeBuildInputs = [ makeWrapper ];
    passthru = {
      inherit password-jars;
      inherit (password-jars) mitmCache;
    };
    meta = password-jars.meta // {
      description = "Desktop app of the password-java password manager";
      mainProgram = "password-gui";
      # the jar bundles skiko for linux-x64 only (compose.desktop.currentOs at build time)
      platforms = [ "x86_64-linux" ];
    };
  }
  ''
    # the full JDK, because the headless one lacks AWT
    makeWrapper ${lib.getExe jdk25} $out/bin/password-gui \
      --add-flags "--enable-native-access=ALL-UNNAMED -jar ${password-jars}/share/password/app.jar" \
      --prefix LD_LIBRARY_PATH : ${libraryPath}
    install -Dm644 ${desktopItem} $out/share/applications/at.yawk.password.desktop
  ''
