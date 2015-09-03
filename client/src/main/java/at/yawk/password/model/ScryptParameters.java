package at.yawk.password.model;

import com.lambdaworks.crypto.SCrypt;
import java.security.GeneralSecurityException;
import lombok.SneakyThrows;
import lombok.Value;
import lombok.experimental.Wither;
import lombok.extern.slf4j.Slf4j;

/**
 * @author yawkat
 */
@Value
@Slf4j
@Wither
public class ScryptParameters {
    private final int expN;
    private final int r;
    private final int p;
    private final int dkLen;
    private final byte[] salt;

    @SneakyThrows(GeneralSecurityException.class)
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

    private byte[] doRunScrypt(byte[] password) throws GeneralSecurityException {
        return SCrypt.scrypt(password, salt, 1 << expN, r, p, dkLen);
    }
}
