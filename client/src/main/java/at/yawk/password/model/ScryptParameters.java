package at.yawk.password.model;

import lombok.Value;
import lombok.With;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.generators.SCrypt;

/**
 * @author yawkat
 */
@Value
@Slf4j
@With
public class ScryptParameters {
    private final int expN;
    private final int r;
    private final int p;
    private final int dkLen;
    private final byte[] salt;

    public byte[] runScrypt(byte[] password) {
        if (log.isDebugEnabled()) {
            log.debug("Hashing password with parameters {}", this);
            long start = System.currentTimeMillis();
            byte[] key = doRunScrypt(password);
            long end = System.currentTimeMillis();
            log.debug("Hashing took {} ms", end - start);
            return key;
        } else {
            return doRunScrypt(password);
        }
    }

    private byte[] doRunScrypt(byte[] password) {
        return SCrypt.generate(password, salt, 1 << expN, r, p, dkLen);
    }
}
