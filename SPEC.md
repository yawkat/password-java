# Specification

This describes the protocol between client and server and the format of the stored database, as implemented in
`shared` (`AuthProtocol`, `Base32`), `client` (`VaultClient`, `PasswordClient`, `VaultKey`, `VaultStore`,
`DatabaseClient`, `KeyMaterial`, `BlobCodec`, `LegacyBlob`, `otp/*`, `passkey/*`, `model/*`) and `server`
(`DatabaseController`, `Vaults`, `DatabaseState`, `SignatureFilter`, `UnregisteredFilter`, `WebHeadersFilter`).

The server stores one opaque blob per vault and never sees a password or the plaintext. There are two vaults: the
password vault, opened with the master password, and the [2FA vault](#2fa-vault), opened with its own password. Both
use the same protocol. One key derivation from a vault's password gives both the key that signs the client's requests
and the keys that encrypt the blob. The server only stores the public half of the signing key.

All numbers are big-endian. `‖` is concatenation. `hex` is lowercase hexadecimal.

## Security goals

- **Auth is no weaker than the database.** Anyone holding the encrypted database can test password guesses at the
  cost of one key derivation each; that is inherent, since a new device only needs the password. What the server
  stores and what goes over the wire must not allow anything cheaper. Checking a guess against the stored public
  key costs the same Argon2id run as checking it against the database, and the salt is per installation, so nothing
  can be precomputed.
- **Nothing captured can be reused.** A request is signed together with its method, path, body, a timestamp and a
  nonce, and the server accepts each nonce once. A stolen registration file can't sign requests.
- **No additional secret.** A new device needs only the server URL and the master password.
- **The server can't choose parameters.** The key derivation parameters are fixed by the protocol version, the only
  value the server or a stored blob chooses. An unknown version is an error.

Out of scope: the server itself can always guess passwords offline (it has the database), and whoever registers a
fresh server first owns it. The emergency web client (below) is code served by the server, so while it is used, the
server is trusted not to serve a page that leaks the password.

## Master password

The client encodes the master password as UTF-8 (`password` below).

## Key derivation

Protocol version 1, the only one:

```
root         = Argon2id(password, salt = install_salt, memory = 64 MiB, iterations = 4, parallelism = 4, length = 32)
auth_seed    = HKDF-SHA256(ikm = root, salt = none, info = "at.yawk.password/v1/auth", length = 32)
auth_key     = Ed25519 private key with seed auth_seed
blob_key     = HKDF-SHA256(ikm = root, salt = blob_salt, info = "at.yawk.password/v1/container", length = 32)
```

Argon2id is version 0x13 without secret or associated data. `install_salt` is 32 random bytes chosen by the client
that registers the server (see below). `blob_salt` is 32 random bytes chosen for every saved blob, so every blob has
its own key. `KeyMaterialTest` pins these steps against libargon2 and OpenSSL.

## HTTP protocol

The server speaks plain HTTP; TLS is expected to be provided by a reverse proxy. Request and response bodies are raw
bytes (`application/octet-stream` responses). Requests with a body larger than 4 MB are rejected with 413.

### `GET /salt`

| Status | Body                                                   |
|--------|--------------------------------------------------------|
| 200    | `version (1 byte) ‖ install_salt (32 bytes)`           |
| 404    | The server is not registered yet                       |

Unauthenticated: the salt is not secret.

### `PUT /register`

The body is `version (1 byte, = 1) ‖ install_salt (32 bytes) ‖ Ed25519 public key of auth_key (32 bytes)`.

| Status | Meaning                                                |
|--------|--------------------------------------------------------|
| 200    | Stored as `verifier` in the data directory             |
| 400    | Malformed (length, version, public key)                |
| 403    | The server is registered already; nothing changes    |

The registration can only be set once, and is not authenticated: the first client to reach a fresh server claims it.
The 403 is sent before the body is read. Registering deletes `shared-secret`, the credential of the old protocol.

### Authentication of `/db`

Requests to `/db` carry the header

```
X-Auth: <timestamp> <nonce> <signature>
```

- `timestamp`: the client's clock in unix milliseconds, decimal;
- `nonce`: 16 random bytes, lowercase hex;
- `signature`: hex of the Ed25519 signature by `auth_key` of the text

```
at.yawk.password/v1/request\n
<timestamp>\n
<nonce>\n
<method>\n
<path>\n
<hex(SHA-256(body))>\n
```

where `method` is the HTTP method (`GET`, `PUT`, and `HEAD` for a HEAD request), `path` is the request path
(`/db`), and `body` is the request body (empty for `GET`). The text can be built with `printf` and signed with
`openssl pkeyutl -sign -rawin`, see `nix/nixos-test.nix`.

There is no challenge. The server checks, in this order:

1. Backoff: after 5 failed signatures in a row, all `/db` requests get 429 for 1 s, then 2 s, 4 s, ... up to one
   hour, doubling with every further failure. A valid signature resets the count. The state is kept in memory.
   (An attacker can keep the owner locked out this way; that is the price of limiting online guessing.)
2. The header is well-formed and the server is registered, else 403.
3. `|server time − timestamp| ≤ 60 s`, else 401 with a `Date` header. The client then retries once with its clock
   corrected by the difference to `Date`.
4. The nonce was not used by an accepted request, else 403.
5. After the body has been read, steps 1-4 again, except that the timestamp may now be up to 120 s away (the
   upload may have been slow). Then the signature, else 403, which counts towards the backoff.

Steps 1-4 happen before the body is read. On success the nonce is remembered until the server clock is more than
120 s past its timestamp, so every request is accepted at most once. This also holds if the server clock steps back;
only a forward jump followed by a step back can make a request from before the jump acceptable once more. At most
10,000 nonces are remembered; beyond that, the one with the oldest timestamp is forgotten early. A server restart forgets the nonces; a request replayed within a minute of that is accepted once more, which
only returns or stores what the original request did.

### `GET /db`

| Status | Body                                                   |
|--------|--------------------------------------------------------|
| 200    | The stored encrypted blob                              |
| 401    | Timestamp out of range                                 |
| 403    | Invalid or replayed request                            |
| 404    | No database of this registration has been stored yet   |
| 429    | Backoff                                                |

Only a stored blob with the header of this registration (magic, version, install salt) is returned. In particular,
the database of the old protocol, which a migrated server still has in its data directory, is never served: it
would give whoever registers the server first an offline password oracle.

### `PUT /db`

The body is the new encrypted blob. The server checks its header: the magic, version 1 and the registered
`install_salt`, so that no client can store a blob that other clients can't read.

| Status | Meaning                                                |
|--------|--------------------------------------------------------|
| 200    | Stored                                                 |
| 400    | Not a blob of this registration                        |
| 401, 403, 429 | As for `GET /db`                                |
| 413    | Body larger than 4 MB                                  |

### Emergency web client

Other `GET` paths serve the emergency web client, the static files in `server/src/main/resources/web`: `/` (or
`/index.html`), `/app.js`, `/app.css` and `/argon2.js` (Argon2id of hash-wasm). Anything else gets 404.

All responses of the server, the API included, carry a `Content-Security-Policy` that only allows same-origin
scripts, styles and requests plus WebAssembly, and `Cache-Control: no-store` (`WebHeadersFilter`).

The page is a read-only client: it loads as in [Client behaviour](#client-behaviour), without a local copy, and never
registers or saves. It requests `salt` and `db` relative to its own URL, but signs the path `/db`. For the 2FA vault
it requests `totp/salt` and `totp/db`, signs `/totp/db`, and computes the codes with WebCrypto's HMAC.

### Server storage

Each `PUT /db` writes a new file in the data directory, named by the current time in ISO-8601 UTC
(`Instant.toString()`, e.g. `2026-09-26T16:54:45.392616657Z`), then deletes the symlink `latest` and creates it again
pointing to the new file by its bare name (a relative target, so the link works however the data directory was
given and if it is moved). `GET /db` returns the content of `latest`. Old files are never deleted. If the symlink
cannot be created (e.g. on FAT or some SMB mounts), the request fails and `latest` stays deleted, so `GET /db` returns
404 until a later upload succeeds. The client's local copy uses the same code.
On POSIX file systems, `verifier` and the database files are created with mode `0600`.

### 2FA vault

The 2FA vault holds the TOTP secrets and backup codes. It works exactly like the password vault, with the paths
`/totp/salt`, `/totp/register` and `/totp/db` instead of `/salt`, `/register` and `/db`. It has its own password (the
"backup password"), install salt, registration, nonces and backoff, and is stored in the subdirectory `totp` of the
data directory (created with mode `0700` when the 2FA vault is registered), in the same layout. Registering one vault doesn't register the
other: the first client that saves to `/totp/db` claims the 2FA vault, like the password vault.

The signed path is `/totp/db`, so a request signed for one vault is never accepted by the other, even if both had the
same key. The blob format is the same, and the server checks the header against the 2FA vault's registration.

The master password doesn't open the 2FA vault, so both factors are not behind the same password. The server holds
both encrypted vaults; each costs one Argon2id run per guess of its own password.

## Encrypted blob

This is the body of `GET /db` and `PUT /db` and the content of the stored files.

```
header     = "PWDB" ‖ version (1 byte, = 1) ‖ install_salt (32) ‖ blob_salt (32) ‖ nonce (12)
plaintext  = len(json) (4 bytes) ‖ json ‖ zero bytes up to a multiple of 4096 bytes
blob       = header ‖ AES-256-GCM(key = blob_key, nonce, aad = header).encrypt(plaintext)    (with the 16-byte tag)
```

- `json` is the UTF-8 JSON of the decrypted blob (below).
- The padding hides the exact size of the database.
- `blob_salt` and `nonce` are random for every save.
- The whole header is authenticated. A wrong password and a modified blob both fail the GCM tag check, and can't be
  told apart.
- `install_salt` in the header tells the client which keys to use, so that the local copy can be opened without the
  server.

### Legacy blobs

The old format (scrypt parameters and salt, then AES-CFB of `HMAC-SHA512 ‖ json`) is only read, for the one-time
migration of a local copy (see the README). Only the parameters every old client wrote are accepted (scrypt
N = 2^16, r = 8, p = 1, 32-byte key and salt).

## Decrypted blob (JSON)

```json
{
  "data": {
    "passwords": [
      {
        "name": "example.com",
        "value": "hunter2\nuser: alice\nnotes..."
      }
    ]
  },
  "revision": 42
}
```

| Field                    | Type            | Meaning                                                              |
|--------------------------|-----------------|----------------------------------------------------------------------|
| `data`                   | object          | The password database                                                |
| `data.passwords`         | array           | Entries, in display order                                            |
| `data.passwords[].name`  | string          | Entry name                                                           |
| `data.passwords[].value` | string          | Free text. By convention, the first line (up to `\n` or `\r`) is the password; the rest holds username, notes and so on. |
| `data.passkeys`          | array           | Passkeys (below), in the order they were added. Left out while empty. |
| `revision`               | integer         | Incremented by every save (0 in legacy blobs)                        |
| `minReaderVersion`       | integer         | Reader schema version, see [Schema versions](#schema-versions). Left out while 0. |
| `minWriterVersion`       | integer         | Writer schema version, see [Schema versions](#schema-versions). Left out while 0. |

A passkey (WebAuthn credential) in `data.passkeys`. Binary values are base64url without padding, as in WebAuthn's JSON:

```json
{
  "id": "0b7c4c1e-2a5d-4f43-9b0e-6d1f3e2a9c41",
  "rpId": "example.com",
  "credentialId": "6sJ0p8b1...",
  "userHandle": "dXNlci0xMjM",
  "userName": "alice@example.com",
  "userDisplayName": "Alice",
  "privateKey": "Fh3x...",
  "created": 1761736800000
}
```

| Field             | Type    | Meaning                                                                         |
|-------------------|---------|---------------------------------------------------------------------------------|
| `id`              | string  | Random UUID, to tell passkeys apart                                             |
| `rpId`            | string  | Relying party ID, e.g. `example.com`                                            |
| `credentialId`    | string  | Credential ID, 32 random bytes                                                  |
| `userHandle`      | string  | `user.id` of the relying party, 1 to 64 bytes                                   |
| `userName`        | string  | `user.name`, may be empty                                                       |
| `userDisplayName` | string  | `user.displayName`, may be empty                                                |
| `privateKey`      | string  | ECDSA P-256 private scalar, 32 bytes big-endian. The public key is derived from it. |
| `created`         | integer | Milliseconds since the epoch                                                    |

`passkeys` is left out of the JSON while it is empty, so that clients that predate passkeys (which reject unknown
fields) keep opening the database until the first passkey is created. Adding a passkey with the `rpId` and
`userHandle` of an existing one replaces it, as an authenticator does for discoverable credentials.

The 2FA vault has the same `revision`, and `data` holds its accounts:

```json
{
  "data": {
    "accounts": [
      {
        "id": "6f1c0a52-8d0e-4c1e-9f3b-2a8f4d6e7b90",
        "type": "totp",
        "issuer": "GitHub",
        "label": "alice",
        "secret": "JBSWY3DPEHPK3PXP",
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
        "backupCodes": "abcd-1234\nefgh-5678"
      }
    ]
  },
  "revision": 3
}
```

| Field                            | Type    | Meaning                                                              |
|----------------------------------|---------|----------------------------------------------------------------------|
| `data.accounts`                  | array   | Accounts, in display order                                           |
| `data.accounts[].id`             | string  | Random UUID, to tell accounts apart                                  |
| `data.accounts[].type`           | string  | `totp`, the only type so far                                         |
| `data.accounts[].issuer`         | string  | The service, may be empty                                            |
| `data.accounts[].label`          | string  | The account at the service, may be empty                             |
| `data.accounts[].secret`         | string  | Base32 (RFC 4648), upper case, without padding or separators         |
| `data.accounts[].algorithm`      | string  | HMAC of the TOTP: `SHA1`, `SHA256` or `SHA512`                       |
| `data.accounts[].digits`         | integer | Code length, 6 to 10                                                 |
| `data.accounts[].period`         | integer | Seconds per code, e.g. 30, or 10 for Authy's own tokens              |
| `data.accounts[].backupCodes`    | string  | Free text: the account's backup codes and anything kept with them    |
| `data.accounts[].favorite`       | boolean | Shown at the top of the list. Since writer version 1                 |

The code at unix time `t` is the HOTP (RFC 4226) of the counter `floor(t / period)`, truncated to `digits` digits
(RFC 6238).

### Schema versions

Each vault has two schema versions of its own, so that a change to one vault doesn't affect the other: the password
vault is at reader 0 and writer 0, the 2FA vault at reader 0 and writer 1 (`favorite`). They are in
`PasswordBlob.VERSIONS` and `OtpBlob.VERSIONS`.

- The **writer version** is raised with every change to the data, e.g. a new field or a new enum value.
- The **reader version** is raised as well when even a client that only reads must not ignore the change, e.g.
  anything that changes how a code is computed, what a secret means, or which relying party a passkey may be used
  for: a client that ignored it would act wrongly rather than just show less.

A client writes its own versions as `minReaderVersion` and `minWriterVersion` on every save. When it loads data:

- With a higher `minReaderVersion` than its reader version, it refuses to open it, as for an unknown protocol version.
- Otherwise, with a higher `minWriterVersion` than its writer version, it opens it read-only: it skips the fields it
  doesn't know, reads unknown enum values as missing, and refuses every save, since a save would drop what it skipped.
  If it picks the local copy over such a server copy (`SERVER_COPY_OLDER`), that is read-only too.
- Otherwise, it reads the data strictly: a field it doesn't know is an error. So a change that forgot to raise the
  writer version makes older clients refuse the data, rather than drop part of it on the next save.

The data is authenticated with the vault's key, so the versions and any new fields come from another client of the
same user, not from the server. Clients that predate schema versions reject any unknown field, including the version
fields themselves: they can't open a vault once a newer client saved it with a version above 0. The web client only
reads, so it only checks the reader version.

## Client behaviour

Non-2xx responses are errors, including redirects that the HTTP client does not follow (e.g. from `http` to
`https`). Connecting times out after 15 seconds, and waiting for data after 60 seconds. Responses larger than 4 MB
are errors.

The client keeps a local copy of the encrypted blob in the same layout as the server's data directory (timestamped
files plus `latest`). Keys are derived once per install salt and kept in memory while unlocked.

### Load

1. `GET /salt`.
   - 404: the server is not registered. Use the local copy if there is one, marked "not on server"; otherwise there
     is no database yet, and the apps ask the user to repeat the master password (`ConfirmCreate`) before creating an
     empty one. **Loading never registers**: that only happens on the first save, so entering a URL does not claim a
     server. The registration always gets a **new install salt**, also when the content comes from a local copy of an
     earlier registration, so a vault that was reset never comes back with its old keys (see [Exported
     keys](#exported-keys)). The local copy is still decrypted with the keys of its own install salt, so a password
     that doesn't decrypt it is rejected as wrong.
   - Otherwise derive the keys for the install salt and `GET /db`. A 404 there means that no database was saved
     yet: use the local copy if there is one, marked "not on server", or else there is no database yet, as above.
     The next save uploads without registering.
2. If a request fails (network error, 403, 429, ...), use the local copy, marked "server unavailable"; without a
   local copy the error is raised. A failed load leaves nothing to save: the client must load successfully first. A wrong password gets 403 from the server and then fails to decrypt the local copy,
   so it is reported as a wrong password. Saves keep using the server's install salt if it is known, else that of the
   local copy. A legacy local copy has none, so it can't be saved until the server is reachable.
3. Otherwise decrypt the remote blob.
   - If that fails, fall back to the local copy ("server copy invalid"). If there is no local copy, or it also fails,
     the remote error is raised.
   - If the local copy has the same install salt and a **higher revision**, use the local copy ("server copy older"):
     the server copy was rolled back, or our last upload failed (the local copy is written first). The client can't
     tell the two apart. The local copy is not replaced.
   - Otherwise save the remote blob as the new local copy and use it. The remote blob is only saved locally once it
     has been verified, so a corrupt or foreign blob on the server never replaces the local copy.

### Save

Each modification encrypts the whole database with revision + 1, a new blob salt and nonce, then:

1. writes the blob to the local copy;
2. if the last load found the server unregistered, registers it with `PUT /register`;
3. uploads the blob with `PUT /db`.

If a request fails, the local copy already contains the new blob and the error is raised. The client does not merge:
a save replaces whatever the server had, including after the database was loaded from the local copy. The apps ask
for confirmation before the first save in that state.

### Exported keys

Instead of the password, a client can open a vault with an exported key: `install_salt ‖ root` (64 bytes), taken
from a client that was unlocked with the password, and only once the server has accepted its keys (a signed request
for the database, or the registration). It opens and saves the vault without the Argon2id run, but only for that
install salt: for another one (e.g. after the vault on the server was reset and created again, which always gives a
new install salt) it fails like a wrong password. An exported key never registers: if the server has no registration,
the vault was reset. Then the client opens a local copy of its own install salt, marked "vault reset"; a save only
reaches the local copy and then fails, until the vault is unlocked with its password. So resetting the 2FA vault
locks out the exported keys of all devices, e.g. that of a lost phone. The Android app keeps the 2FA vault's exported key encrypted by a Keystore key that needs a
fingerprint, so that a fingerprint opens the 2FA vault. The exported key opens the vault as the password does, so it
is kept as safe as the data.

### Passkeys

The apps are a WebAuthn authenticator for the passkeys of the database (`PasskeyAuthenticator`):

- Algorithm ES256 (COSE -7) only; the signature is ASN.1 DER over `authenticatorData ‖ clientDataHash`.
- Attestation format `none`, AAGUID all zero.
- `authenticatorData` = `SHA-256(rpId) ‖ flags ‖ counter (4 bytes, always 0)`, then for a registration the attested
  credential data (`AAGUID ‖ len(credentialId) (2 bytes) ‖ credentialId ‖ COSE_Key`). Flags: UP (`0x01`), UV
  (`0x04`), BE (`0x08`) and BS (`0x10`), plus AT (`0x40`) for a registration. Approving in the unlocked app counts as
  user verification.
- The COSE_Key is the CTAP2 canonical CBOR map `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.

The Android app is a credential provider (`PasskeyProviderService`), which takes and returns WebAuthn's JSON
(`WebAuthnJson`). For a browser of the privileged list it uses the origin that the browser names, which must be the
relying party ID or a subdomain of it, and signs the `clientDataHash` the browser passes. For any other app, the
origin is `android:apk-key-hash:<base64url(SHA-256(signing certificate))>`, the app must be named in the relying
party's Digital Asset Links, and the provider makes `clientDataJSON` itself.

The desktop app is a CTAP 2.0 security key on a Linux `uhid` device (`fido/*`): CTAPHID (init, ping, wink, CBOR,
cancel, keepalive; no U2F), and the CTAP2 commands `authenticatorMakeCredential`, `authenticatorGetAssertion` and
`authenticatorGetInfo`. It reports `rk`, `up` and `uv` (built-in user verification) and no PIN protocol, and returns
one assertion: the user chooses the passkey in the app. A `getAssertion` with `up: false` (a browser checking an
allow list) is answered from the unlocked database without asking, with neither UP nor UV set; while the database is
locked it finds nothing.

### Apps

Both apps copy only the first line of an entry (the password) on a plain copy, and clear the clipboard after 30
seconds if it still holds what they copied.

The Android app additionally:

- marks copied text as sensitive (`android.content.extra.IS_SENSITIVE`), and recognizes its own copies by their clip
  description. The 30 seconds are an inexact alarm, so it may be a little later. Android only lets the focused app
  look at the clipboard; when the time runs out while the app is in the background, it clears the clipboard without
  checking.
- locks after five minutes in the background (or right away when it comes back later than that), discarding unsaved
  edits. Locking does not wait for a running request: its result is discarded, and the master password is wiped
  once it is done.
- keeps its window out of screenshots and the recent apps (`FLAG_SECURE`), and asks the keyboard not to learn from
  the master password and entry fields.
