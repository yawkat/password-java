package at.yawk.password.client;

import at.yawk.password.PlatformDependent;
import com.lambdaworks.crypto.SCrypt;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * @author yawkat
 */
class AsymmetricKdf {
    // scrypt parameters
    private static final int N_EXP = 10;
    private static final int R = 8;
    private static final int P = 1;
    private static final int DK_LEN = 32;
    // we can't really use a salt for KDF so use something simple
    private static final byte[] SALT = "kdf".getBytes();
    // this is relatively low for performance, it isn't that important to security anyway
    private static final int RSA_KEY_SIZE = 1024;

    static KeyPair getRsaKeyPair(byte[] password) throws GeneralSecurityException {
        byte[] hash = SCrypt.scrypt(password, SALT, 1 << N_EXP, R, P, DK_LEN);
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(hash);

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE, rng);
        return gen.generateKeyPair();
    }
}
