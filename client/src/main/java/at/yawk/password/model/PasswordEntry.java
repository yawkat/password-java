package at.yawk.password.model;

import lombok.Data;
import lombok.ToString;

/**
 * @author yawkat
 */
@Data
public class PasswordEntry {
    private String name;
    /**
     * The secret (first line: password). Excluded from {@link #toString()} so it never ends up in logs; this also
     * covers everything that prints entries, such as {@link PasswordBlob} and {@link DecryptedBlob}.
     */
    @ToString.Exclude
    private String value;
}
