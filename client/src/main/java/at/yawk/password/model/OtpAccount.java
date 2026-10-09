package at.yawk.password.model;

import at.yawk.password.Base32;
import java.util.UUID;
import lombok.Data;
import lombok.ToString;
import org.jetbrains.annotations.Nullable;

/**
 * One account of the 2FA vault: the TOTP parameters and the account's backup codes.
 *
 * <p>The setters keep the text fields non-null (a JSON {@code null} becomes empty) and the secret canonical, so that
 * the same account compares equal however it was entered.
 *
 * @author yawkat
 */
@Data
public class OtpAccount {
    public static final String TYPE_TOTP = "totp";

    /**
     * Random, to tell accounts apart: issuer and label may be empty, and need not be unique.
     */
    private String id = UUID.randomUUID().toString();
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
     * Base32, in the canonical form of {@link Base32#canonical} if it is valid. Excluded from {@link #toString()}, like
     * {@link PasswordEntry#getValue()}.
     */
    @ToString.Exclude
    @Nullable private String secret;
    private OtpAlgorithm algorithm = OtpAlgorithm.SHA1;
    private int digits = 6;
    /**
     * In seconds.
     */
    private int period = 30;
    /**
     * Free text: the backup codes of the account, and anything else to keep with them.
     */
    @ToString.Exclude
    private String backupCodes = "";

    public void setIssuer(@Nullable String issuer) {
        this.issuer = issuer == null ? "" : issuer.trim();
    }

    public void setLabel(@Nullable String label) {
        this.label = label == null ? "" : label.trim();
    }

    public void setBackupCodes(@Nullable String backupCodes) {
        this.backupCodes = backupCodes == null ? "" : backupCodes;
    }

    /**
     * An invalid secret is kept as it is, so that a vault holding one still loads; it fails when generating codes.
     */
    public void setSecret(@Nullable String secret) {
        if (secret != null) {
            try {
                secret = Base32.canonical(secret);
            } catch (IllegalArgumentException ignored) {
            }
        }
        this.secret = secret;
    }
}
