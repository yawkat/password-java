# Specification

This describes the protocol between client and server and the format of the stored database, as implemented in
`shared` (`AuthProtocol`), `client` (`PasswordClient`, `DatabaseClient`, `KeyMaterial`, `BlobCodec`, `LegacyBlob`,
`model/*`) and `server` (`DatabaseController`, `DatabaseState`, `SignatureFilter`, `UnregisteredFilter`,
`WebHeadersFilter`).

The server stores one opaque blob and never sees the master password or the plaintext. One key derivation from the
master password gives both the key that signs the client's requests and the keys that encrypt the blob. The server
only stores the public half of the signing key.

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
registers or saves. It requests `salt` and `db` relative to its own URL, but signs the path `/db`.

### Server storage

Each `PUT /db` writes a new file in the data directory, named by the current time in ISO-8601 UTC
(`Instant.toString()`, e.g. `2026-09-26T16:54:45.392616657Z`), then deletes the symlink `latest` and creates it again
pointing to the new file. `GET /db` returns the content of `latest`. Old files are never deleted. If the symlink
cannot be created (e.g. on FAT or some SMB mounts), the request fails and `latest` stays deleted, so `GET /db` returns
404 until a later upload succeeds. With a relative data directory other than `.`, the link target is wrong and the
link dangles ([#27](https://github.com/yawkat/password-java/issues/27)). The client's local copy uses the same code.
On POSIX file systems, `verifier` and the database files are created with mode `0600`.

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
| `revision`               | integer         | Incremented by every save (0 in legacy blobs)                        |

## Client behaviour

Non-2xx responses are errors, including redirects that the HTTP client does not follow (e.g. from `http` to
`https`). Connecting times out after 15 seconds, and waiting for data after 60 seconds. Responses larger than 4 MB
are errors.

The client keeps a local copy of the encrypted blob in the same layout as the server's data directory (timestamped
files plus `latest`). Keys are derived once per install salt and kept in memory while unlocked.

### Load

1. `GET /salt`.
   - 404: the server is not registered. Use the local copy if there is one (a legacy local copy is decrypted with
     the password and gets a new install salt), marked "not on server"; otherwise there is no database yet, and the
     apps ask the user to repeat the master password (`ConfirmCreate`) before creating an empty one. **Loading never
     registers**: that only happens on the first save, so entering a URL does not claim a server.
   - Otherwise derive the keys for the install salt and `GET /db`. A 404 there means that no database was saved
     yet: use the local copy if there is one, marked "not on server", or else there is no database yet, as above.
     The next save uploads without registering.
2. If a request fails (network error, 403, 429, ...), use the local copy, marked "server unavailable"; without a
   local copy the error is raised. A wrong password gets 403 from the server and then fails to decrypt the local copy,
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
