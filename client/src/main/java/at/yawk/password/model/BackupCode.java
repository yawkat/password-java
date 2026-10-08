package at.yawk.password.model;

import lombok.Data;
import lombok.ToString;

/**
 * A single-use recovery code of an {@link OtpAccount}.
 *
 * @author yawkat
 */
@Data
public class BackupCode {
    @ToString.Exclude
    private String code;
    /**
     * Marked by the user once the code was used up.
     */
    private boolean used;
}
