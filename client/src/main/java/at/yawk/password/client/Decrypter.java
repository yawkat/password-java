package at.yawk.password.client;

import at.yawk.password.model.DecryptedBlob;
import at.yawk.password.model.EncryptedBlob;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lambdaworks.crypto.SCrypt;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageDecoder;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * @author yawkat
 */
@RequiredArgsConstructor
@Slf4j
class Decrypter extends MessageToMessageDecoder<EncryptedBlob> {
    static final int HMAC_LENGTH = 64;

    private final ObjectMapper objectMapper;
    private final byte[] password;

    @Override
    protected void decode(ChannelHandlerContext ctx, EncryptedBlob msg, List<Object> out)
            throws Exception {
        DecryptedBlob decrypted = decrypt(objectMapper, password, msg);
        out.add(decrypted);
    }

    static byte[] scrypt(byte[] password, byte[] salt, int n, int r, int p, int dkLen) throws GeneralSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Hashing password with parameters n={} r={} p={} dkLen={}", n, r, p, dkLen);
            long start = System.currentTimeMillis();
            byte[] key = SCrypt.scrypt(password, salt, n, r, p, dkLen);
            long end = System.currentTimeMillis();
            log.debug("Hashing took {} ms", end - start);
            return key;
        } else {
            return SCrypt.scrypt(password, salt, n, r, p, dkLen);
        }
    }

    static DecryptedBlob decrypt(ObjectMapper objectMapper, byte[] password, EncryptedBlob msg) throws Exception {
        byte[] key = scrypt(
                password,
                msg.getSalt(),
                1 << msg.getExpN(),
                msg.getR(),
                msg.getP(),
                msg.getDkLen()
        );
        Cipher decryptCipher = Cipher.getInstance("AES/CFB/NoPadding");
        decryptCipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(msg.getIv())
        );
        byte[] dec = decryptCipher.doFinal(msg.getBody());

        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        // use content
        mac.update(dec, HMAC_LENGTH, dec.length - HMAC_LENGTH);
        byte[] expectedMac = mac.doFinal();

        for (int i = 0; i < HMAC_LENGTH; i++) {
            if (dec[i] != expectedMac[i]) {
                throw new Exception(
                        "Invalid HMAC: expected " +
                        DatatypeConverter.printHexBinary(expectedMac).toLowerCase() +
                        " but was " +
                        DatatypeConverter.printHexBinary(Arrays.copyOf(dec, HMAC_LENGTH))
                                .toLowerCase()
                );
            }
        }

        return objectMapper.reader()
                .forType(DecryptedBlob.class)
                .readValue(dec, HMAC_LENGTH, dec.length - HMAC_LENGTH);
    }
}
