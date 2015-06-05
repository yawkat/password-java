Network Layout
==============

- The client asks for a password and encodes it as `UTF-8` for further use.
- The client sends `GET /` to the server.
- The server responds with the encrypted blob (described below) or a 404
    + If 404 is received, the following steps are ignored and an empty decrypted blob is generated on the client instead.
    + The client uses the parameters from the encrypted blob together with the password bytes (see above) to derive the AES decryption key via scrypt.
    + The client decrypts the blob with the AES key, unzips it and reads the decrypted contents.
- When the blob needs to be saved:
    + The client zips and encrypts the decrypted blob.
    + The client signs the encrypted blob using the private key.
    + The client sends a `POST /` request with the signed blob as the body to the server.
    + The server receives the signed blob.
        * If we have an old blob saved, we confirm that the new blob is signed with the same public key.
    + The server stores the encrypted blob to be returned by `GET /`.

Password storage format
=======================

The base data (password json) will be called `raw data`.

Decrypted Blob Format
---------------------

The decrypted blob is a simple json document. The RSA keys are generated on first upload.

```
{
    "rsa": {
        "private": "<private RSA key as PKCS8 base64>",
        "public": "<public RSA key as X509 base64>"
    },
    "data": <raw data>
}
```

Encrypted Blob Format
---------------------

All numbers are big-endian.
- int = 32 bits = 4 bytes

```
int     expN        The exponent of the 'N' parameter (N = 2**expN) of the scrypt key derivation function
int     r           The 'r' parameter for scrypt
int     p           The 'p' parameter for scrypt
int     dkLen       Size of the derived key in bytes
int     salt_len    Length of the following salt in bytes
byte[]  salt        Byte array of the scrypt salt, length defined in previous field
byte[]  iv          IV of the encrypted body
int     body_len    Length of the encrypted body
byte[]  body        Encrypted Body
```

### Encrypted Body

- GZIP `decrypted body`
- Prepend HMAC-SHA512 header
- Encrypt using AES with the key derived from the parameters and the password and CFB cipher block mode using a random IV.

Signed Blob Format
------------------

```
int     key_len     Length of the public RSA key
byte[]  key         RSA public key, encoded as X509 DER
byte[]  signature   SHA512-RSA signature (always 64 bytes)
int     body_len    Length of the encrypted body
byte[]  body        Encrypted blob using the 'encrypted blob' format above
```
