# password-java

A self-hosted password manager with client-side encryption. The client encrypts the password database with a key
derived from the master password and stores the resulting blob on a small HTTP server. The server never sees the
master password or the plaintext. See [SPEC.md](SPEC.md) for the protocol and the file format.

One Argon2id run over the master password gives both the encryption keys and a key that signs every request to the
server. The server only stores the public key. Neither it nor what goes over the wire lets anyone test password
guesses more cheaply than against the encrypted database itself, and a captured request can't be replayed or reused
for another request. A new device only needs the URL and the master password. Whoever holds the encrypted database,
including the server, can still guess passwords offline at the cost of one Argon2id run (64 MiB) per guess: choose a
strong master password. See [SPEC.md](SPEC.md#security-goals).

## Modules

| Module   | Contents                                                                                           |
|----------|----------------------------------------------------------------------------------------------------|
| `shared` | Protocol constants, local file storage and hashing helpers used by both client and server (Java 17) |
| `client` | Protocol client, key derivation and encryption (Argon2id, Ed25519, AES-GCM) and the `PasswordStore` model (Java 17) |
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
| `verifier`                       | The registration: install salt and the client's public key, set by the first client that saves (see SPEC.md) |
| `<timestamp>`, e.g. `2026-09-26T16:54:45.392616657Z` | One encrypted database per upload, named by its ISO-8601 UTC time. Old versions are never deleted. |
| `latest`                         | Symlink to the newest database file                                        |
| `totp/`                          | The 2FA vault, with its own password, in the same layout (`verifier`, timestamped files, `latest`). Created at startup. See [SPEC.md](SPEC.md#2fa-vault). |

Files are created owner-only (`rw-------`). The server logs a warning at startup if the data directory is accessible
by other users. The data directory must support symlinks: on a file system without them (FAT, some SMB mounts) every
upload fails, and `latest` is left deleted.

### Registration

A fresh server has no `verifier`. The first client that *saves* to it registers it, unauthenticated, with the master
password it was given (see [SPEC.md](SPEC.md#client-behaviour)). Loading never registers: on a fresh server the app
asks you to repeat the master password and create an empty database, and the first entry you add registers the
server. Other devices then just unlock with the same URL and password.

Register right after deploying, before the port is reachable by others (before setting `openFirewall` or exposing it
through a proxy).

After 5 failed signatures in a row, the server refuses requests (429) for a second, doubling with every further
failure up to an hour. This limits online password guessing, at the price that someone who can reach the server can
keep you out for a while.

### Emergency web access

For when no device with the app is at hand (say, a lost phone while travelling), the server serves a read-only web
client at `/`: open the server URL in a browser and enter the master password. It lists the entries with a search
field, can show or copy a password, and locks after five minutes without activity. It can't change anything. A copied
password is cleared from the clipboard after 30 seconds. Browsers only allow that while the page has focus, so
otherwise it is cleared when you return to the page, even if you have copied something else since. If you close the
page before, the password stays in the clipboard. Behind a reverse proxy that serves the server below a path, open that path with a trailing slash
(`https://example.com/pw/`), since the page loads everything relative to its URL.

The page runs the same protocol as the apps in the browser: Argon2id through WebAssembly
([hash-wasm](https://github.com/Daninet/hash-wasm), taken from its webjar at build time), and WebCrypto for the rest.
The key derivation takes a few seconds, longer on a slow phone. It needs HTTPS and a browser with Ed25519 in WebCrypto
(Firefox 129, Chrome 137, Safari 17 or later).

The master password still never goes to the server, but the server now supplies the code that handles it: whoever
controls the server or the TLS proxy can serve a page that sends the password elsewhere. With the apps, that takes
compromising the device. And every device you type the master password into can read the whole database, so use a
device you trust, in a private window.

To reset a server, stop it and delete `verifier` and `latest` from the data directory. The next client that saves
registers it again. This is also the only way to change the master password: the client that registers with the new
password starts with an empty database (or with its local copy, if that is in the new format and it can decrypt it).
The old timestamped files stay in place, encrypted under the old password. The 2FA vault is reset the same way, with
`totp/verifier` and `totp/latest`, independently of the password vault.

### Migrating from the old protocol

Servers and clients of the old protocol (shared secret, `/challenge`) don't work with the new ones. To migrate:

1. With the old client, unlock once so that its local copy is current.
2. Deploy the new server. It keeps the old database files, but never serves them, and ignores the `shared-secret`.
3. Unlock with the new desktop app (same `storageDir`) and the same master password. The server has no registration
   yet, so the app opens the local copy of the old format ("Server has no database, loaded local copy"). Make any
   change (e.g. add and delete an entry) and confirm the upload: this registers the server with a new install salt,
   uploads the database in the new format, and deletes `shared-secret`.
4. Other devices, e.g. the Android app, just unlock. They fetch the new database and replace their old local copy.

Anyone who can reach the server between steps 2 and 3 can register it first, so do them back to back or keep the
server unreachable until step 3 is done.

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
tests in `android/src/androidTest` run the risky parts (Jackson, BouncyCastle's Argon2id and Ed25519, AES-GCM, the
local storage) on a device; CI runs them on an API 29 emulator. To run them on a connected device or emulator:

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

This runs the server as a hardened systemd service `password-server`. Register (see [Registration](#registration)) before
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
