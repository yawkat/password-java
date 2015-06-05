package at.yawk.password.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

/**
 * @author yawkat
 */
@Data
public class DecryptedBlob {
    private RsaKeyPair rsa = new RsaKeyPair();
    private JsonNode data;

    @Data
    public static class RsaKeyPair {
        @JsonProperty("private")
        private String privateKey;
        @JsonProperty("public")
        private String publicKey;
    }
}
