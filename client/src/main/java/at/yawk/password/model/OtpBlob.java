package at.yawk.password.model;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.jetbrains.annotations.Nullable;

/**
 * The content of the 2FA vault, the counterpart of {@link PasswordBlob}.
 *
 * @author yawkat
 */
@Data
public class OtpBlob {
    private List<OtpAccount> accounts = new ArrayList<>();

    /**
     * {@code null} (for the list or an element, only written by other software) is read as nothing.
     */
    public void setAccounts(@Nullable List<OtpAccount> accounts) {
        this.accounts = new ArrayList<>();
        if (accounts != null) {
            for (OtpAccount account : accounts) {
                if (account != null) {
                    this.accounts.add(account);
                }
            }
        }
    }
}
