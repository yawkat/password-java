package at.yawk.password.model;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
     * {@code null} (for the list or an element) is read as nothing, and an account whose id an earlier one has gets a
     * new id, which is kept from the next save on: accounts are identified by id, so ids must be unique. Only other
     * software writes such data.
     */
    public void setAccounts(@Nullable List<OtpAccount> accounts) {
        this.accounts = new ArrayList<>();
        if (accounts != null) {
            Set<String> ids = new HashSet<>();
            for (OtpAccount account : accounts) {
                if (account != null) {
                    if (!ids.add(account.getId())) {
                        account.setId(null);
                        ids.add(account.getId());
                    }
                    this.accounts.add(account);
                }
            }
        }
    }
}
