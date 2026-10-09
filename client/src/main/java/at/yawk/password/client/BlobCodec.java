package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import at.yawk.password.HashUtil;
import at.yawk.password.model.DecryptedBlob;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.experimental.UtilityClass;
import org.jetbrains.annotations.Nullable;

/**
 * The encrypted database format, see SPEC.md:
 * {@code "PWDB" ‖ version ‖ install salt ‖ blob salt ‖ nonce ‖ AES-256-GCM(len ‖ json ‖ padding)}, with the header
 * as associated data. The key is derived from the {@link KeyMaterial} and the random blob salt, so every blob has its
 * own key.
 *
 * @author yawkat
 */
@UtilityClass
class BlobCodec {
    private static final int TAG_BITS = 128;
    /**
     * The plaintext is padded to a multiple of this, so the blob size only roughly reveals the database size.
     */
    static final int PADDING = 4096;

    static byte[] encrypt(ObjectMapper objectMapper, KeyMaterial keys, DecryptedBlob<?> msg) throws Exception {
        ByteBuffer header = ByteBuffer.allocate(AuthProtocol.BLOB_HEADER_LENGTH);
        header.put(AuthProtocol.BLOB_MAGIC);
        header.put((byte) AuthProtocol.VERSION);
        header.put(keys.getInstallSalt());
        byte[] blobSalt = HashUtil.generateRandomBytes(AuthProtocol.BLOB_SALT_LENGTH);
        header.put(blobSalt);
        byte[] nonce = HashUtil.generateRandomBytes(AuthProtocol.BLOB_NONCE_LENGTH);
        header.put(nonce);

        byte[] json = objectMapper.writeValueAsBytes(msg);
        int paddedLength = (4 + json.length + PADDING - 1) / PADDING * PADDING;
        byte[] plaintext = ByteBuffer.allocate(paddedLength).putInt(json.length).put(json).array();
        byte[] key = keys.containerKey(blobSalt);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(header.array());
            byte[] ciphertext = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(header.capacity() + ciphertext.length)
                    .put(header.array())
                    .put(ciphertext)
                    .array();
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(json, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    /**
     * @return The install salt of a blob in this format, or {@code null} if it is not one (e.g. a legacy blob).
     */
    @Nullable
    static byte[] installSalt(byte[] blob) {
        if (blob.length < AuthProtocol.BLOB_HEADER_LENGTH ||
            !Arrays.equals(Arrays.copyOf(blob, AuthProtocol.BLOB_MAGIC.length), AuthProtocol.BLOB_MAGIC)) {
            return null;
        }
        return Arrays.copyOfRange(blob, AuthProtocol.BLOB_INSTALL_SALT_OFFSET,
                                  AuthProtocol.BLOB_INSTALL_SALT_OFFSET + AuthProtocol.SALT_LENGTH);
    }

    static <T> DecryptedBlob<T> decrypt(ObjectMapper objectMapper, KeyMaterial keys, byte[] blob, Class<T> dataClass)
            throws Exception {
        byte[] installSalt = installSalt(blob);
        if (installSalt == null || blob.length < AuthProtocol.BLOB_HEADER_LENGTH + TAG_BITS / 8) {
            throw new Exception("Invalid database: bad header");
        }
        if (blob[AuthProtocol.BLOB_MAGIC.length] != AuthProtocol.VERSION) {
            throw new Exception("Invalid database: unsupported version " + blob[AuthProtocol.BLOB_MAGIC.length]);
        }
        if (!keys.hasInstallSalt(installSalt)) {
            throw new IllegalArgumentException("Keys are for a different install salt");
        }
        ByteBuffer header = ByteBuffer.wrap(blob, 0, AuthProtocol.BLOB_HEADER_LENGTH);
        header.position(AuthProtocol.BLOB_INSTALL_SALT_OFFSET + AuthProtocol.SALT_LENGTH);
        byte[] blobSalt = new byte[AuthProtocol.BLOB_SALT_LENGTH];
        header.get(blobSalt);
        byte[] nonce = new byte[AuthProtocol.BLOB_NONCE_LENGTH];
        header.get(nonce);

        byte[] key = keys.containerKey(blobSalt);
        byte[] plaintext = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(blob, 0, AuthProtocol.BLOB_HEADER_LENGTH);
            try {
                plaintext = cipher.doFinal(blob, AuthProtocol.BLOB_HEADER_LENGTH,
                                           blob.length - AuthProtocol.BLOB_HEADER_LENGTH);
            } catch (AEADBadTagException e) {
                throw new WrongPasswordException();
            }
            // authenticated, so a bad length is a bug on the writing side rather than an attack
            int length = ByteBuffer.wrap(plaintext).getInt();
            if (length < 0 || length > plaintext.length - 4) {
                throw new Exception("Invalid database: bad length");
            }
            return objectMapper.readerFor(decryptedType(objectMapper, dataClass)).readValue(plaintext, 4, length);
        } finally {
            Arrays.fill(key, (byte) 0);
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    static JavaType decryptedType(ObjectMapper objectMapper, Class<?> dataClass) {
        return objectMapper.getTypeFactory().constructParametricType(DecryptedBlob.class, dataClass);
    }
}
