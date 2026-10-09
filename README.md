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

The server speaks plain HTTP. Put a TLS-terminating reverse proxy in front of it. Requests larger than 4 MB are
rejected with 413.

The data directory contains:

| File                             | Contents                                                                  |
|----------------------------------|---------------------------------------------------------------------------|
| `verifier`                       | The registration: install salt and the client's public key, set by the first client that saves (see SPEC.md) |
| `<timestamp>`, e.g. `2026-09-26T16:54:45.392616657Z` | One encrypted database per upload, named by its ISO-8601 UTC time. Old versions are never deleted. |
| `latest`                         | Symlink to the newest database file                                        |
| `totp/`                          | The 2FA vault, with its own password, in the same layout (`verifier`, timestamped files, `latest`). Created when the 2FA vault is registered. See [SPEC.md](SPEC.md#2fa-vault). |

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

With *2FA codes* selected, the page opens the [2FA vault](#2fa-codes) with the backup password instead: it shows the
current code of every account (computed in the browser), copies it like a password, and shows the backup codes on
request. This is for the case the 2FA codes are kept for: the phone is lost.

The page runs the same protocol as the apps in the browser: Argon2id through WebAssembly
([hash-wasm](https://github.com/Daninet/hash-wasm), taken from its webjar at build time), and WebCrypto for the rest.
The key derivation takes a few seconds, longer on a slow phone. It needs HTTPS and a browser with Ed25519 in WebCrypto
(Firefox 129, Chrome 137, Safari 17 or later).

The master password still never goes to the server, but the server now supplies the code that handles it: whoever
controls the server or the TLS proxy can serve a page that sends the password elsewhere. With the apps, that takes
compromising the device. And every device you type the master password into can read the whole database, so use a
device you trust, in a private window. The same holds for the backup password and the 2FA codes. Don't open both
vaults on a device you don't trust: that would put both factors in one place.

To reset a server, stop it and delete `verifier` and `latest` from the data directory. The next client that saves
registers it again, with a new install salt. A client with the same password and a local copy uploads the content of
its local copy. This is also the only way to change the master password: register with the new password from a device
without a local copy (or delete the local copy first), which starts with an empty database. A device with a local copy
rejects the new password, since it can't decrypt that copy. The old timestamped files stay in place, encrypted under
the old password.

The 2FA vault is reset the same way, with `totp/verifier` and `totp/latest`, independently of the password vault.
This also locks out the devices that open it with a fingerprint, e.g. a lost phone: they need the vault's password
again.

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

Put `storageDir` on a file system with symlinks. A relative path resolves against the working directory.

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

## 2FA codes

The apps also keep TOTP codes ("2FA codes", as in Google Authenticator or Authy) and the backup codes of each
account, in a vault of their own on the same server (see [SPEC.md](SPEC.md#2fa-vault)). It has its own password, the
*backup password*: the master password doesn't open it, so the password database and the second factors are never
behind the same password. Choose a strong backup password that differs from the master password, and keep it written
down somewhere safe. It is what opens your 2FA codes when your phone is lost.

Open the vault with *2FA codes* on the unlock screen. The first time, the app offers to create it. Then:

- Click or tap an account to copy its current code. Codes are cleared from the clipboard after 30 seconds, like
  passwords. Shortly before a code expires, the next one is shown as well.
- *Add* scans the QR code with the camera (Android), takes its `otpauth://` link (most sites show the link or the
  secret key next to the code), or the fields by hand. Codes with other parameters than 6 digits every 30 seconds work too, e.g. 7 digits every 10 seconds
  for the sites that use Authy's own tokens, such as Cloudflare. HOTP (counter-based) and Steam codes are not supported.
- Each account has a free text field for its backup codes. Keep them here rather than in the password database.
- The vault locks after five minutes without activity, and on Android as soon as the app goes to the background (after
  a minute if an account is being edited, e.g. while you copy its secret from the browser).

The local copy of the vault is kept in `storageDir/totp` (desktop) or in the app's private storage (Android).

### Fingerprint (Android)

After you open the vault with the backup password, the app offers to open it with your fingerprint from then on.
Opening the 2FA codes (and coming back to the app after it locked them) then takes nothing but the fingerprint. The app
keeps the vault's key (not the backup password) encrypted by a key in the Android Keystore, which only a strong
biometric check unlocks, every time. The key belongs to the server it was enabled for, and is only used for that one.

- Enrolling another fingerprint keeps it working. So whoever knows the phone's PIN can add their finger and open the
  2FA codes; keep the PIN as safe as the codes.
- Removing the screen lock destroys it. The app then asks for the backup password, and offers the fingerprint again.
- *Forget fingerprint* on the lock screen deletes it.
- Resetting the 2FA vault on the server (see [Registration](#registration)) locks out the fingerprint of every phone
  that reaches the server, e.g. of a lost one: it deletes its key and needs the backup password again. A phone kept
  offline still opens its local copy with the fingerprint, so after losing a phone, also regenerate the codes of
  important accounts.

### Migrating from Authy

Authy has no export. Its desktop app, which the old export tricks relied on, was discontinued. The ways that still
work, as of 2026:

1. **iOS and mitmproxy:** intercept the Authy app's sync and decrypt the tokens with your Authy backup password. Ente's
   [migration guide](https://ente.com/help/auth/migration/authy/) describes it. The result is a list of `otpauth://`
   links.
2. **A rooted Android phone:** read the tokens from the Authy app's data.
3. **Enroll again:** turn 2FA off and on again at each site and add the new QR code. This always works, and also
   replaces secrets that Twilio has had. Consider it at least for important accounts, and for Authy's own tokens
   (Cloudflare and others) wherever the site now offers standard TOTP.

Then use *Import* in the 2FA vault: paste the links (one per line) or, on the desktop, open the file. The preview shows
the current code of every account: compare them with Authy before you import, and before you delete anything there.
Lines that can't be read are listed with the reason; accounts that are in the vault already are skipped.

Move the backup codes from the password database into the matching accounts, and then generate new backup codes at
each site: the server never deletes old versions of the password database, so the old codes stay in them.

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
