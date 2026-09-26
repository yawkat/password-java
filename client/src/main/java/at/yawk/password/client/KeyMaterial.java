package at.yawk.password.client;

import at.yawk.password.AuthProtocol;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * The keys derived from the master password and the install salt: one Argon2id run gives the root key, from which
 * HKDF derives the Ed25519 authentication key and the per-blob container keys.
 *
 * <p>The Argon2id parameters are fixed by {@link AuthProtocol#VERSION}. They are never read from the server or a
 * blob, so neither can make the client do more (or less) work.
 *
 * @author yawkat
 */
@Slf4j
final class KeyMaterial {
    /**
     * Argon2id with 64 MiB, 4 passes and 4 lanes. Stronger than the scrypt (N=2^16, r=8) of the old container, and
     * still faster than the old unlock, which ran scrypt twice.
     */
    static final int ARGON2_MEMORY_KIB = 64 * 1024;
    static final int ARGON2_ITERATIONS = 4;
    static final int ARGON2_PARALLELISM = 4;
    private static final int KEY_LENGTH = 32;

    private static final byte[] AUTH_INFO = "at.yawk.password/v1/auth".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CONTAINER_INFO = "at.yawk.password/v1/container".getBytes(StandardCharsets.UTF_8);

    private final byte[] installSalt;
    private final byte[] rootKey;
    private final Ed25519PrivateKeyParameters authKey;

    private KeyMaterial(byte[] installSalt, byte[] rootKey) {
        this.installSalt = installSalt.clone();
        this.rootKey = rootKey;
        byte[] seed = hkdf(rootKey, null, AUTH_INFO);
        this.authKey = new Ed25519PrivateKeyParameters(seed);
        Arrays.fill(seed, (byte) 0);
    }

    static KeyMaterial derive(byte[] password, byte[] installSalt) {
        if (installSalt.length != AuthProtocol.SALT_LENGTH) {
            throw new IllegalArgumentException("Invalid install salt length");
        }
        long start = System.nanoTime();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                               .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                               .withMemoryAsKB(ARGON2_MEMORY_KIB)
                               .withIterations(ARGON2_ITERATIONS)
                               .withParallelism(ARGON2_PARALLELISM)
                               .withSalt(installSalt)
                               .build());
        byte[] rootKey = new byte[KEY_LENGTH];
        generator.generateBytes(password, rootKey);
        log.debug("Key derivation took {} ms", (System.nanoTime() - start) / 1_000_000);
        return new KeyMaterial(installSalt, rootKey);
    }

    byte[] getInstallSalt() {
        return installSalt.clone();
    }

    byte[] getPublicKey() {
        return authKey.generatePublicKey().getEncoded();
    }

    byte[] sign(byte[] message) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, authKey);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    /**
     * The AES-256-GCM key of one blob, identified by its random blob salt.
     */
    byte[] containerKey(byte[] blobSalt) {
        return hkdf(rootKey, blobSalt, CONTAINER_INFO);
    }

    boolean hasInstallSalt(byte[] salt) {
        return Arrays.equals(installSalt, salt);
    }

    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[KEY_LENGTH];
        hkdf.generateBytes(out, 0, out.length);
        return out;
    }
}
