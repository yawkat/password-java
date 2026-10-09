package at.yawk.password.model;

import lombok.Data;

/**
 * The JSON content of an encrypted blob: the vault's data ({@link PasswordBlob} or {@link OtpBlob}) and its revision.
 *
 * @author yawkat
 */
@Data
public class DecryptedBlob<T> {
    private T data;
    /**
     * Incremented on every save. A client refuses to replace its local copy with a remote copy of a lower revision,
     * so a server can't silently roll the database back to a version older than the one the client has. Legacy
     * databases have none (0).
     */
    private long revision;
}
