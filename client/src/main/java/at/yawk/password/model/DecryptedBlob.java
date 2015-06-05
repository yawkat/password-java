package at.yawk.password.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * @author yawkat
 */
@Data
public class DecryptedBlob {
    private RsaKeyPair rsa = new RsaKeyPair();
    private PasswordBlob data;

    @Data
    public static class RsaKeyPair {
        @JsonProperty("private")
        private String privateKey;
        @JsonProperty("public")
        private String publicKey;
    }
}
