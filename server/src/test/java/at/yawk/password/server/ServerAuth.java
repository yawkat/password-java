package at.yawk.password.server;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * A client's keys for the server tests: a random Ed25519 key pair and install salt, and request signing as in
 * {@code DatabaseClient}.
 */
final class ServerAuth {
    final byte[] salt = HashUtil.generateRandomBytes(AuthProtocol.SALT_LENGTH);
    final KeyPair keyPair;

    ServerAuth() throws GeneralSecurityException {
        keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    byte[] registration() {
        byte[] encoded = keyPair.getPublic().getEncoded();
        byte[] body = new byte[AuthProtocol.REGISTRATION_LENGTH];
        body[0] = AuthProtocol.VERSION;
        System.arraycopy(salt, 0, body, 1, salt.length);
        // the raw key is the end of the X.509 encoding
        System.arraycopy(encoded, encoded.length - AuthProtocol.PUBLIC_KEY_LENGTH, body, 1 + salt.length,
                         AuthProtocol.PUBLIC_KEY_LENGTH);
        return body;
    }

    String header(long timestamp, String method, String path, byte[] body) throws GeneralSecurityException {
        String nonce = HexFormat.of().formatHex(HashUtil.generateRandomBytes(AuthProtocol.NONCE_LENGTH));
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keyPair.getPrivate());
        signature.update(AuthProtocol.signingInput(timestamp, nonce, method, path, body));
        return timestamp + " " + nonce + " " + HexFormat.of().formatHex(signature.sign());
    }

    String header(String method, String path, byte[] body) throws GeneralSecurityException {
        return header(System.currentTimeMillis(), method, path, body);
    }

    /**
     * A database of the given size with a valid header for this registration and random content.
     */
    byte[] database(int size) {
        byte[] db = HashUtil.generateRandomBytes(size);
        System.arraycopy(AuthProtocol.BLOB_MAGIC, 0, db, 0, AuthProtocol.BLOB_MAGIC.length);
        db[AuthProtocol.BLOB_MAGIC.length] = AuthProtocol.VERSION;
        System.arraycopy(salt, 0, db, AuthProtocol.BLOB_INSTALL_SALT_OFFSET, salt.length);
        return db;
    }

    static byte[] withByte(byte[] data, int index, int value) {
        byte[] copy = Arrays.copyOf(data, data.length);
        copy[index] = (byte) value;
        return copy;
    }
}
