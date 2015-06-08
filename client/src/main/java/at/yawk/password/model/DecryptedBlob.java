package at.yawk.password.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import lombok.Data;

/**
 * @author yawkat
 */
@Data
public class DecryptedBlob {
    private RsaKeyPair rsa;
    private PasswordBlob data;

    @Data
    public static class RsaKeyPair {
        @JsonProperty("private")
        private String privateKey;
        @JsonProperty("public")
        private String publicKey;

        public static RsaKeyPair ofKeyPair(KeyPair keyPair) {
            RsaKeyPair k = new RsaKeyPair();
            k.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            k.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            return k;
        }

        public KeyPair toKeyPair() throws GeneralSecurityException {
            byte[] priEnc = Base64.getDecoder().decode(getPrivateKey());
            byte[] pubEnc = Base64.getDecoder().decode(getPublicKey());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return new KeyPair(
                    keyFactory.generatePublic(new X509EncodedKeySpec(pubEnc)),
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(priEnc))
            );
        }
    }
}
