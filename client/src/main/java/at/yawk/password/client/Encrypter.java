package at.yawk.password.client;

import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lambdaworks.crypto.SCrypt;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageEncoder;
import java.security.SecureRandom;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
class Encrypter extends MessageToMessageEncoder<DecryptedBlob> {
    // scrypt parameters
    private static final int N_EXP = 18;
    private static final int R = 8;
    private static final int P = 1;
    private static final int DK_LEN = 32;

    private final ObjectMapper objectMapper;
    private final byte[] password;

    private static byte[] generateSalt() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[32];
        rng.nextBytes(salt);
        return salt;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, DecryptedBlob msg, List<Object> out)
            throws Exception {
        EncryptedBlob encryptedBlob = encrypt(objectMapper, password, msg);

        out.add(encryptedBlob);
    }

    public static EncryptedBlob encrypt(ObjectMapper objectMapper, byte[] password, DecryptedBlob msg)
            throws Exception {
        byte[] salt = generateSalt();
        byte[] key = SCrypt.scrypt(
                password,
                salt,
                1 << N_EXP, R, P,
                DK_LEN
        );

        byte[] body = objectMapper.writeValueAsBytes(msg);
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        byte[] hmac = mac.doFinal(body);

        Cipher encryptCipher = Cipher.getInstance("AES/CFB");
        encryptCipher.init(DK_LEN * 8, new SecretKeySpec(key, "AES"));
        encryptCipher.update(hmac);
        encryptCipher.update(body);

        EncryptedBlob encryptedBlob = new EncryptedBlob();
        encryptedBlob.setDkLen(DK_LEN);
        encryptedBlob.setExpN(N_EXP);
        encryptedBlob.setR(R);
        encryptedBlob.setP(P);
        encryptedBlob.setSalt(salt);
        encryptedBlob.setIv(encryptCipher.getIV());
        encryptedBlob.setBody(encryptCipher.doFinal());
        return encryptedBlob;
    }
}
