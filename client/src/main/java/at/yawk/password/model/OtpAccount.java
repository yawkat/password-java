package at.yawk.password.model;

import at.yawk.password.otp.OtpAlgorithm;
import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import lombok.ToString;

/**
 * One account of the 2FA vault: the TOTP parameters and the account's backup codes.
 *
 * @author yawkat
 */
@Data
public class OtpAccount {
    public static final String TYPE_TOTP = "totp";

    /**
     * Only {@value #TYPE_TOTP} for now. Stored, so that other types (HOTP, Steam) can be added without guessing.
     */
    private String type = TYPE_TOTP;
    /**
     * The service, e.g. "GitHub". May be empty.
     */
    private String issuer = "";
    /**
     * The account at the service, e.g. the user name. May be empty.
     */
    private String label = "";
    /**
     * Base32 (normalized: upper case, no padding or separators). Excluded from {@link #toString()}, like
     * {@link PasswordEntry#getValue()}.
     */
    @ToString.Exclude
    private String secret;
    private OtpAlgorithm algorithm = OtpAlgorithm.SHA1;
    private int digits = 6;
    /**
     * In seconds.
     */
    private int period = 30;
    @ToString.Exclude
    private List<BackupCode> backupCodes = new ArrayList<>();
    @ToString.Exclude
    private String notes = "";
}
