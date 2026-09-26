# password-java

A self-hosted password manager with client-side encryption. The client encrypts the password database with a key
derived from the master password and stores the resulting blob on a small HTTP server. The server never sees the
master password or the plaintext. See [SPEC.md](SPEC.md) for the protocol and the file format.

The server does store a password verifier: the *shared secret*, a cheap scrypt hash of the master password with a
global salt. Anyone who obtains it, or one challenge and token observed on the wire, can test password guesses offline
much faster than against the encrypted database itself. See [SPEC.md](SPEC.md#shared-secret) and
[#8](https://github.com/yawkat/password-java/issues/8).

## Modules

| Module   | Contents                                                                                           |
|----------|----------------------------------------------------------------------------------------------------|
| `shared` | Local file storage and hashing helpers used by both client and server (Java 17)                    |
| `client` | Protocol client, encryption (scrypt, AES, HMAC) and the `PasswordStore` model (Java 17)            |
| `server` | The database server, a Micronaut 5 application (Java 25)                                           |
| `app`    | The GUI, a Compose Multiplatform application built on `client`: the desktop app (`password-gui`) and the Android target |
| `android`| The Android app, a thin shell around `app`                                                         |

## Building with Gradle

You need JDK 25. Gradle 9.8 comes with the wrapper. The Android app also needs the Android SDK (see
[Android app](#android-app)); leave it out with `-Ppassword.android=false` if you don't have one.

```sh
./gradlew build
```

This compiles all modules and runs the tests.

Gradle properties:

- `-Ppassword.app=false` leaves out the `app` module, and with it the Android app. The desktop app bundles native
  Skiko libraries for the build platform, so use this where you only need the server and client.
- `-Ppassword.android=false` leaves out the Android app (and the Android target of `app`), so the build needs no
  Android SDK. The nix build uses this.

Useful tasks:

| Task                                       | Result                                                                   |
|--------------------------------------------|--------------------------------------------------------------------------|
| `./gradlew :server:installDist`            | Server distribution in `server/build/install/server` (`bin/server`, `lib/`) |
| `./gradlew :app:run`                       | Starts the desktop app                                                   |
| `./gradlew :app:packageUberJarForCurrentOS` | Desktop app jar in `app/build/compose/jars/password-gui-<os>-<arch>-1.0.0.jar` |

## Running the server

```sh
./gradlew :server:installDist
server/build/install/server/bin/server -p 8080 -d /var/lib/password
```

| Option | Default | Meaning                   |
|--------|---------|---------------------------|
| `-p`   | `8080`  | TCP port, on all interfaces |
| `-d`   | `.`     | Data directory            |

Pass `-d` as an absolute path (or leave it at `.`). With a relative path such as `-d data`, the `latest` symlink
points to the wrong place and the server cannot read back what it stored
([#27](https://github.com/yawkat/password-java/issues/27)).

The server speaks plain HTTP. Put a TLS-terminating reverse proxy in front of it. Requests larger than 4 MB are
rejected with 413.

The data directory contains:

| File                             | Contents                                                                  |
|----------------------------------|---------------------------------------------------------------------------|
| `shared-secret`                  | The client credential, set by the first client that connects (see SPEC.md) |
| `<timestamp>`, e.g. `2026-09-26T16:54:45.392616657Z` | One encrypted database per upload, named by its ISO-8601 UTC time. Old versions are never deleted. |
| `latest`                         | Symlink to the newest database file                                        |

Files are created owner-only (`rw-------`). The server logs a warning at startup if the data directory is accessible
by other users. The data directory must support symlinks: on a file system without them (FAT, some SMB mounts) every
upload fails, and `latest` is left deleted.

### Enrollment

A fresh server has no `shared-secret`. The first client that connects sets it, unauthenticated, from the master
password it was given (see [SPEC.md](SPEC.md#client-behaviour)). This happens when the client first *loads* the
database, before the app asks you to confirm creating a new one. A mistyped master password therefore claims
the server permanently, and the correct password is rejected from then on.

Enroll right after deploying, before the port is reachable by others (before setting `openFirewall` or exposing it
through a proxy): open the desktop or Android app with the new server's URL and your master password, and confirm
creating the database.

To reset a server, stop it and delete `shared-secret` and `latest` from the data directory. Also delete `latest` in
each client's `storageDir`, since the client would otherwise fall back to the local copy and fail to decrypt it. The
next client that connects enrolls again. This is also the only way to change the master password: an existing
database cannot be re-encrypted, so the new one starts empty. The old timestamped files stay in place, encrypted
under the old password.

## Desktop app

The app reads `$XDG_CONFIG_HOME/password-gui/config.properties` (`~/.config/password-gui/config.properties` if
`XDG_CONFIG_HOME` is unset):

```properties
url=https://pw.example.com
storageDir=~/.local/share/password
```

| Key          | Default                                                        | Meaning                                         |
|--------------|----------------------------------------------------------------|-------------------------------------------------|
| `url`        | `https://pw.yawk.at`                                           | Server base URL, without a trailing slash       |
| `storageDir` | `$XDG_DATA_HOME/password` (`~/.local/share/password`)          | Local copy of the database. A leading `~` is expanded. |

Set `url` to your own server: the default is the author's. You can also enter the URL on the unlock screen.

Use an absolute path (or `~/...`) for `storageDir`, on a file system with symlinks. A relative path breaks the
`latest` symlink as it does for the server's `-d` ([#27](https://github.com/yawkat/password-java/issues/27)).

The local copy uses the same layout as the server's data directory (timestamped files plus `latest`). The app writes
`url` back to the file when you change the server URL in the UI. Other keys are kept, comments are not.

If the server is unreachable, the app opens the local copy and warns before saving changes made offline.

## Android app

The Android app (applicationId `at.yawk.password.android`, the same as the old
[password-android](https://github.com/yawkat/password-android)) runs on Android 10 (API 29) and later. It uses the
same server and database as the desktop app.

Building it needs the Android SDK: set `ANDROID_HOME`, or `sdk.dir` in a `local.properties` file (which git ignores).
The Android Gradle Plugin downloads missing SDK packages if their licenses have been accepted.

```sh
./gradlew :android:assembleDebug     # android/build/outputs/apk/debug/android-debug.apk
./gradlew :android:assembleRelease   # android/build/outputs/apk/release/android-release-unsigned.apk
```

The repository has no release signing configuration: sign the release APK yourself (e.g. with `apksigner`), or
install the debug build. `./gradlew build` builds both and runs Android Lint, which fails on uses of APIs newer than
API 29 in our code.

Libraries can still call JDK methods that older Android versions lack, which only fails at runtime. The instrumented
tests in `android/src/androidTest` run the risky parts (Jackson, BouncyCastle's scrypt, the local storage) on a
device; CI runs them on an API 29 emulator. To run them on a connected device or emulator:

```sh
./gradlew :android:connectedDebugAndroidTest
```

The app keeps the server URL in its settings (default `https://pw.yawk.at`; enter your own on the unlock screen) and
the local copy of the database in its private storage. It locks after five minutes in the background, and removes a
copied password from the clipboard after about 30 seconds. Debug builds also allow plain HTTP to `localhost` and
`127.0.0.1`, e.g. to a test server reached through `adb reverse`; release builds require HTTPS.

## Building with nix

The flake supports `x86_64-linux` and `aarch64-linux`.

```sh
nix build .#server   # result/bin/password-server, takes the same -p and -d options
nix build .#app      # result/bin/password-gui, x86_64-linux only
nix run              # the default package: app on x86_64-linux, server elsewhere
nix develop          # shell with JDK 25 and Gradle
nix flake check -L   # builds everything except the Android app, runs the Gradle tests and a NixOS VM test of the module
```

### Using the flake from a NixOS configuration

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.password-java = {
    url = "github:yawkat/password-java";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = inputs@{ nixpkgs, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        inputs.password-java.nixosModules.default
        {
          services.password-server.enable = true;
        }
      ];
    };
  };
}
```

This runs the server as a hardened systemd service `password-server`. Enroll (see [Enrollment](#enrollment)) before
setting `openFirewall` or exposing the port. Options under `services.password-server`:

| Option         | Default               | Meaning                                                                   |
|----------------|-----------------------|---------------------------------------------------------------------------|
| `enable`       | `false`               | Enable the service                                                        |
| `port`         | `8080`                | Listen port (all interfaces)                                              |
| `dataDir`      | `/var/lib/password`   | Data directory. Must be an absolute path without whitespace or `%`, and not below `/home`, `/root` or `/run/user`. |
| `openFirewall` | `false`               | Open `port` in the firewall                                               |
| `user`, `group`| `password`            | Service account, created automatically when left at the default          |
| `package`      | the flake's `server`  | Server package                                                            |

For the desktop app, add the `app` package in NixOS or home-manager (with `inputs` passed to modules through
`specialArgs` or `extraSpecialArgs`):

```nix
# NixOS
environment.systemPackages = [ inputs.password-java.packages.${pkgs.stdenv.hostPlatform.system}.app ];

# home-manager
home.packages = [ inputs.password-java.packages.${pkgs.stdenv.hostPlatform.system}.app ];
```

It installs `password-gui` and a desktop entry.

### Updating `nix/deps.json`

The nix build fetches Gradle dependencies from the lockfile `nix/deps.json`. After changing any dependency or Gradle
plugin, regenerate it from the repository root on x86_64-linux:

```sh
nix build .#server.mitmCache.updateScript && ./result
```

On other systems the desktop app is not built, so its dependencies would be left out of the lockfile. Stage new
files first (`git add`), since the flake only sees tracked files.
