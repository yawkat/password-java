package at.yawk.password.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import lombok.Data;
import org.jetbrains.annotations.Nullable;

/**
 * @author yawkat
 */
@Data
public class PasswordBlob {
    public static final SchemaVersions VERSIONS = new SchemaVersions(0, 0);

    private List<PasswordEntry> passwords = new ArrayList<>();
    /**
     * Left out of the JSON while empty: clients that predate passkeys reject unknown fields, so they keep opening a
     * database without passkeys.
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Passkey> passkeys = new ArrayList<>();

    /**
     * {@code null} (for the list or an element) is read as nothing, and a passkey whose id an earlier one has gets a
     * new id, like {@link OtpBlob#setAccounts}.
     */
    public void setPasskeys(@Nullable List<Passkey> passkeys) {
        this.passkeys = new ArrayList<>();
        if (passkeys != null) {
            Set<String> ids = new HashSet<>();
            for (Passkey passkey : passkeys) {
                if (passkey != null) {
                    if (!ids.add(passkey.getId())) {
                        passkey.setId(null);
                        ids.add(passkey.getId());
                    }
                    this.passkeys.add(passkey);
                }
            }
        }
    }
}
