package at.yawk.password.model;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;

/**
 * The content of the 2FA vault, the counterpart of {@link PasswordBlob}.
 *
 * @author yawkat
 */
@Data
public class OtpBlob {
    private List<OtpAccount> accounts = new ArrayList<>();
}
