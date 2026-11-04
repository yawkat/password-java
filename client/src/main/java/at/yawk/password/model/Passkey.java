package at.yawk.password.model;

import java.util.UUID;
import lombok.Data;
import lombok.ToString;
import org.jetbrains.annotations.Nullable;

/**
 * A WebAuthn credential (passkey) of the password vault: an ES256 (ECDSA P-256 with SHA-256) key pair for one relying
 * party. Binary values are base64url without padding, as in WebAuthn's JSON. See
 * {@link at.yawk.password.passkey.PasskeyAuthenticator} for creating and using them.
 *
 * <p>The setters keep the text fields non-null (a JSON {@code null} becomes empty), like those of {@link OtpAccount}.
 *
 * @author yawkat
 */
@Data
public class Passkey {
    /**
     * Random, to tell passkeys apart in the apps. A passkey without one (only written by other software) gets a new
     * one, which is kept from the next save on.
     */
    private String id = UUID.randomUUID().toString();
    /**
     * The relying party, e.g. {@code example.com}.
     */
    private String rpId = "";
    /**
     * The credential ID that the relying party knows the passkey by. Random.
     */
    private String credentialId = "";
    /**
     * The user ID that the relying party chose ({@code user.id}), returned on sign-in.
     */
    private String userHandle = "";
    /**
     * {@code user.name}, e.g. an email address. May be empty.
     */
    private String userName = "";
    /**
     * {@code user.displayName}. May be empty.
     */
    private String userDisplayName = "";
    /**
     * The private scalar of the P-256 key, 32 bytes. Excluded from {@link #toString()}, like
     * {@link PasswordEntry#getValue()}.
     */
    @ToString.Exclude
    private String privateKey = "";
    /**
     * Creation time, milliseconds since the epoch.
     */
    private long created;

    public void setId(@Nullable String id) {
        this.id = id == null ? UUID.randomUUID().toString() : id;
    }

    public void setRpId(@Nullable String rpId) {
        this.rpId = rpId == null ? "" : rpId;
    }

    public void setCredentialId(@Nullable String credentialId) {
        this.credentialId = credentialId == null ? "" : credentialId;
    }

    public void setUserHandle(@Nullable String userHandle) {
        this.userHandle = userHandle == null ? "" : userHandle;
    }

    public void setUserName(@Nullable String userName) {
        this.userName = userName == null ? "" : userName;
    }

    public void setUserDisplayName(@Nullable String userDisplayName) {
        this.userDisplayName = userDisplayName == null ? "" : userDisplayName;
    }

    public void setPrivateKey(@Nullable String privateKey) {
        this.privateKey = privateKey == null ? "" : privateKey;
    }
}
