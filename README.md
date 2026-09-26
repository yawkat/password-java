# password-java

A self-hosted password manager with client-side encryption. The client encrypts the password database with a key
derived from the master password and stores the resulting blob on a small HTTP server. The server never sees the
master password or the plaintext. See [SPEC.md](SPEC.md) for the protocol and the file format.

## Modules

| Module   | Contents                                                                                           |
|----------|----------------------------------------------------------------------------------------------------|
| `shared` | Local file storage and hashing helpers used by both client and server (Java 17)                    |
| `client` | Protocol client, encryption (scrypt, AES, HMAC) and the `PasswordStore` model (Java 17)            |
| `server` | The database server, a Micronaut 5 application (Java 25)                                           |
| `app`    | The desktop GUI (`password-gui`), a Compose Multiplatform application built on `client`           |

## Building with Gradle

You need JDK 25. Gradle 9.8 comes with the wrapper.

```sh
./gradlew build
```

This compiles all modules and runs the tests.

Gradle properties:

- `-Ppassword.app=false` leaves out the `app` module. The desktop app bundles native Skiko libraries for the build
  platform, so use this where you only need the server and client.

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
points to the wrong place and the server cannot read back what it stored.

The server speaks plain HTTP. Put a TLS-terminating reverse proxy in front of it. Requests larger than 4 MB are
rejected with 413.

The data directory contains:

| File                             | Contents                                                                  |
|----------------------------------|---------------------------------------------------------------------------|
| `shared-secret`                  | The client credential, set by the first client that connects (see SPEC.md) |
| `<timestamp>`, e.g. `2026-09-26T16:54:45.392616657Z` | One encrypted database per upload, named by its ISO-8601 UTC time. Old versions are never deleted. |
| `latest`                         | Symlink to the newest database file (a copy if symlinks are unavailable)  |

Files are created owner-only (`rw-------`). The server logs a warning at startup if the data directory is accessible
by other users.

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

The local copy uses the same layout as the server's data directory (timestamped files plus `latest`). The app writes
`url` back to the file when you change the server URL in the UI. Other keys are kept, comments are not.

If the server is unreachable, the app opens the local copy and warns before saving changes made offline.

<!-- android: update when #20 lands -->
## Android

An Android app (`android/` module) is being added in #20. It needs an Android SDK to build; `-Ppassword.android=false`
leaves it out. It targets minSdk 29 and has the application ID `at.yawk.password.android`.

## Building with nix

The flake supports `x86_64-linux` and `aarch64-linux`.

```sh
nix build .#server   # result/bin/password-server, takes the same -p and -d options
nix build .#app      # result/bin/password-gui, x86_64-linux only
nix run              # the default package: app on x86_64-linux, server elsewhere
nix develop          # shell with JDK 25 and Gradle
nix flake check -L   # builds everything, runs the Gradle tests and a NixOS VM test of the module
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

This runs the server as a hardened systemd service `password-server`. Options under `services.password-server`:

| Option         | Default               | Meaning                                                                   |
|----------------|-----------------------|---------------------------------------------------------------------------|
| `enable`       | `false`               | Enable the service                                                        |
| `port`         | `8080`                | Listen port (all interfaces)                                              |
| `dataDir`      | `/var/lib/password`   | Data directory. Must be absolute and not below `/home`, `/root` or `/run/user`. |
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
plugin, regenerate it from the repository root:

```sh
nix build .#server.mitmCache.updateScript && ./result
```

`git add` new files first, since the flake only sees tracked files.
