# Specification

This describes the protocol between client and server and the format of the stored database, as implemented in
`client` (`PasswordClient`, `DatabaseClient`, `AesCodec`, `model/*`) and `server` (`DatabaseController`,
`DatabaseState`, `ChallengeTokenFilter`, `SharedSecretUnsetFilter`).

The server stores one opaque blob and never sees the master password or the plaintext. It authenticates clients with
a *shared secret* derived from the master password. The blob is encrypted with a separate key, also derived from
the master password.

All numbers are big-endian. `int` is a signed 32-bit integer (4 bytes). `‖` is concatenation.

## Master password

The client encodes the master password as UTF-8 (`password` below). Both keys are derived from these bytes.

## Shared secret

```
secret = scrypt(password, salt = "CuRdXw06VaLQhV9K", N = 2^14, r = 8, p = 1, dkLen = 8)
```

The salt is the fixed 16-byte ASCII string above, the same for every user and server. The secret is 8 bytes. The
server stores it verbatim in its data directory as `shared-secret`.

The secret is deliberately short and cheap, but it is still an offline password-guessing oracle, and the global salt
allows precomputation. [#8](https://github.com/yawkat/password-java/issues/8) tracks these weaknesses.

## HTTP protocol

The server speaks plain HTTP; TLS is expected to be provided by a reverse proxy. Request and response bodies are raw
bytes (`application/octet-stream` responses). Requests with a body larger than 4 MB are rejected with 413.

### `GET /challenge`

| Status | Body                                                   |
|--------|--------------------------------------------------------|
| 200    | 32 random bytes, the challenge                         |
| 404    | No shared secret has been set yet                      |

For each challenge, the server remembers the token `SHA-512(secret ‖ challenge)`. Tokens are single-use and expire
one minute after the challenge was issued. At most 10,000 tokens are outstanding; when full, the oldest is evicted.

### `PUT /shared-secret`

The body is the shared secret.

| Status | Meaning                                                |
|--------|--------------------------------------------------------|
| 200    | The secret was stored                                  |
| 403    | A secret is already set; it is left unchanged         |

The secret can only be set once. It is not authenticated: the first client to reach a fresh server claims it. An
empty body stores an empty secret.

### Authentication of `/db`

Requests to `/db` carry the header

```
X-Auth-Token: hex(SHA-512(secret ‖ challenge))
```

where `challenge` is the body of a preceding `GET /challenge`. The client sends lowercase hex; the server accepts
either case. A missing, malformed, unknown, expired or already used token yields 403. The token is checked, and
consumed, before the request body is read. Every `/db` request needs a fresh challenge.

### `GET /db`

| Status | Body                                                   |
|--------|--------------------------------------------------------|
| 200    | The stored encrypted blob                              |
| 403    | Invalid token                                          |
| 404    | No database has been stored yet                        |

### `PUT /db`

The body is the new encrypted blob. The server does not parse or validate it. An empty body is stored as an empty
blob.

| Status | Meaning                                                |
|--------|--------------------------------------------------------|
| 200    | Stored                                                 |
| 403    | Invalid token                                          |
| 413    | Body larger than 4 MB                                  |

### Server storage

Each `PUT /db` writes a new file in the data directory, named by the current time in ISO-8601 UTC
(`Instant.toString()`, e.g. `2026-09-26T16:54:45.392616657Z`), then deletes the symlink `latest` and creates it again
pointing to the new file. `GET /db` returns the content of `latest`. Old files are never deleted. If the symlink
cannot be created (e.g. on FAT or some SMB mounts), the request fails and `latest` stays deleted, so `GET /db` returns
404 until a later upload succeeds. With a relative data directory other than `.`, the link target is wrong and the
link dangles ([#27](https://github.com/yawkat/password-java/issues/27)). The client's local copy uses the same code.
On POSIX file systems, `shared-secret` and the database files are created with mode `0600`.

## Encrypted blob

This is the body of `GET /db` and `PUT /db` and the content of the stored files.

```
int     expN        scrypt cost exponent, N = 2^expN
int     r           scrypt block size
int     p           scrypt parallelization
int     dkLen       Length of the derived key in bytes, also the AES key size
int     salt_len    Length of the salt
byte[]  salt        scrypt salt (salt_len bytes)
byte[]  iv          AES IV, always 16 bytes, no length prefix
int     body_len    Length of the encrypted body
byte[]  body        Encrypted body (body_len bytes)
```

Bytes after `body` are ignored.

### Key derivation

```
key = scrypt(password, salt, N = 2^expN, r, p, dkLen)
```

When writing, the client uses `expN = 16`, `r = 8`, `p = 1`, `dkLen = 32` (AES-256) and a fresh random 32-byte salt
for every save. When reading, it uses whatever parameters the blob contains. A blob can only be read if:

- `1 ≤ expN ≤ 30`, `r ≥ 1`, `p ≥ 1`, `dkLen ≥ 1`, and `128 · r · N ≤ 1 GiB` (checked by `ScryptParameters`);
- `N ≥ 2` and `N < 2^(16·r)`, and `p ≤ (2^31 − 1) / (1024 · r)` (checked by BouncyCastle's scrypt). Given
  `expN ≤ 30`, the `N` bound only matters for `r = 1`, where it means `expN ≤ 15`;
- `dkLen` is 16, 24 or 32, since the key is used directly as the AES key (checked by the AES cipher).

The same `key` is used for AES and for the HMAC.

### Body

```
json      = UTF-8 JSON of the decrypted blob (see below)
mac       = HMAC-SHA512(key, json)                         64 bytes
body      = AES/CFB/NoPadding(key, iv).encrypt(mac ‖ json)
```

- The HMAC is computed over the plaintext JSON only, not over the header fields or the IV.
- `mac ‖ json` is encrypted as one continuous CFB stream (128-bit feedback, the JCE default for `AES/CFB`), so
  `body_len = 64 + len(json)`. There is no padding.
- The IV is 16 random bytes generated for every save.
- There is no compression.

To decrypt, the client derives `key` from the header, decrypts `body`, and splits off the first 64 bytes as `mac`. It
then compares `mac` with `HMAC-SHA512(key, rest)` in constant time and rejects the blob if they differ or if the
plaintext is shorter than 64 bytes. Header fields are not authenticated directly, but changing any of them changes
the key or the plaintext, so the HMAC check fails.

Decrypting with a wrong password also fails this check. In practice that only happens with the local copy: against
the server, a wrong password yields a different shared secret, so `GET /db` is rejected with 403 before any blob is
returned.

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
  }
}
```

| Field                    | Type            | Meaning                                                              |
|--------------------------|-----------------|----------------------------------------------------------------------|
| `data`                   | object          | The password database                                                |
| `data.passwords`         | array           | Entries, in display order                                            |
| `data.passwords[].name`  | string          | Entry name                                                           |
| `data.passwords[].value` | string          | Free text. By convention, the first line (up to `\n` or `\r`) is the password; the rest holds username, notes and so on. |

## Client behaviour

Non-2xx responses are errors, including redirects that the HTTP client does not follow (e.g. from `http` to
`https`).

The client keeps a local copy of the encrypted blob in the same layout as the server's data directory (timestamped
files plus `latest`).

### Enrollment

Every request to `/db` is preceded by `GET /challenge`. If that returns 404, the client sends its raw 8-byte shared
secret with `PUT /shared-secret` and requests the challenge again. It does this for any URL whose `/challenge`
returns 404, including a mistyped URL or a misconfigured proxy, which then receives the secret.

Enrollment happens during the first load, before the desktop app asks the user to confirm creating a new database.
On a fresh server, whatever master password is entered first, including a mistyped one, claims the server
permanently. There is no protocol to change or reset the secret; the operator has to delete `shared-secret` (and
`latest`, since the old database cannot be decrypted with a new password) on the server.

A 404 from `PUT /shared-secret` is treated the same as a 404 from `GET /db`: as "no database yet" in the load
procedure below. So a URL that returns 404 for everything looks like an empty server. If `/challenge` returns 404 again
after the secret was accepted, the client enrolls again; a 403 there is raised as an error.

### Load

1. Fetch `GET /db`.
2. If that fails (network error or any error status):
   - with a local copy, decrypt and verify the local copy and use it, marked as coming from local storage;
   - without a local copy, a 404 means there is no database yet; any other error is raised. For "no database
     yet", the desktop app asks the user to repeat the master password (`ConfirmCreate`) and only creates an empty
     database if both match. Nothing is uploaded until the first modification.
3. Otherwise decrypt and verify the remote blob.
   - If that fails, fall back to the local copy as above. If there is no local copy, or it also fails, the remote
     error is raised.
   - If it succeeds, save the remote blob as the new local copy and use it. The remote blob is only saved locally
     once it has been verified, so a corrupt or foreign blob on the server never replaces the local copy.

### Save

Each modification encrypts the whole database with a new salt and IV, then:

1. writes the blob to the local copy;
2. uploads it with `PUT /db`.

If the upload fails, the local copy already contains the new blob and the error is raised. The client does not merge:
a save replaces whatever the server had, including after the database was loaded from the local copy. The desktop app
asks for confirmation before the first save in that state.
