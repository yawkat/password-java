package at.yawk.password.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.xml.bind.DatatypeConverter;
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
        private byte[] privateKey;
        @JsonProperty("public")
        private byte[] publicKey;

        public static RsaKeyPair ofKeyPair(KeyPair keyPair) {
            RsaKeyPair k = new RsaKeyPair();
            k.setPrivateKey(keyPair.getPrivate().getEncoded());
            k.setPublicKey(keyPair.getPublic().getEncoded());
            return k;
        }

        public KeyPair toKeyPair() throws GeneralSecurityException {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return new KeyPair(
                    keyFactory.generatePublic(new X509EncodedKeySpec(getPublicKey())),
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(getPrivateKey()))
            );
        }
    }
}
