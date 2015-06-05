package at.yawk.password.model;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;

/**
 * @author yawkat
 */
@Data
public class PasswordBlob {
    private List<PasswordEntry> passwords = new ArrayList<>();
}
