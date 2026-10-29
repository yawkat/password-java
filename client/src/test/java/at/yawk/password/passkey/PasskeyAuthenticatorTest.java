package at.yawk.password.passkey;

import at.yawk.password.HashUtil;
import at.yawk.password.model.Passkey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.bouncycastle.util.BigIntegers;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class PasskeyAuthenticatorTest {
    private static Passkey create() {
        return PasskeyAuthenticator.create("example.com", new byte[]{1, 2, 3}, "alice", "Alice", 1234);
    }

    /**
     * The public key, from the SPKI encoding and checked by the JDK rather than BouncyCastle
     */
    private static PublicKey publicKey(Passkey passkey) throws Exception {
        return KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(PasskeyAuthenticator.spkiPublicKey(passkey)));
    }

    @Test
    public void testCreate() {
        Passkey passkey = create();
        Assert.assertEquals(passkey.getRpId(), "example.com");
        Assert.assertEquals(PasskeyAuthenticator.userHandle(passkey), new byte[]{1, 2, 3});
        Assert.assertEquals(passkey.getUserName(), "alice");
        Assert.assertEquals(passkey.getUserDisplayName(), "Alice");
        Assert.assertEquals(passkey.getCreated(), 1234);
        Assert.assertEquals(PasskeyAuthenticator.credentialId(passkey).length, 32);
        Assert.assertEquals(PasskeyAuthenticator.fromBase64Url(passkey.getPrivateKey()).length, 32);
        Assert.assertFalse(passkey.toString().contains(passkey.getPrivateKey()));
        Assert.assertNotEquals(create().getCredentialId(), passkey.getCredentialId());
        Assert.assertNotEquals(create().getPrivateKey(), passkey.getPrivateKey());
    }

    @Test
    public void testCreateInvalid() {
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> PasskeyAuthenticator.create("", new byte[1], "", "", 0));
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> PasskeyAuthenticator.create("a", new byte[0], "", "", 0));
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> PasskeyAuthenticator.create("a", new byte[65], "", "", 0));
    }

    @Test
    public void testSignature() throws Exception {
        Passkey passkey = create();
        byte[] authData = PasskeyAuthenticator.assertionAuthData("example.com", true);
        byte[] clientDataHash = HashUtil.generateRandomBytes(32);
        byte[] signature = PasskeyAuthenticator.sign(passkey, authData, clientDataHash);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey(passkey));
        verifier.update(authData);
        verifier.update(clientDataHash);
        Assert.assertTrue(verifier.verify(signature));

        verifier.initVerify(publicKey(create()));
        verifier.update(authData);
        verifier.update(clientDataHash);
        Assert.assertFalse(verifier.verify(signature));
    }

    @Test
    public void testAssertionAuthData() {
        byte[] authData = PasskeyAuthenticator.assertionAuthData("example.com", true);
        Assert.assertEquals(authData.length, 37);
        Assert.assertEquals(Arrays.copyOf(authData, 32),
                            PasskeyAuthenticator.sha256("example.com".getBytes(StandardCharsets.US_ASCII)));
        // UP, UV, BE, BS
        Assert.assertEquals(authData[32], 0x1d);
        Assert.assertEquals(Arrays.copyOfRange(authData, 33, 37), new byte[4]);
        Assert.assertEquals(PasskeyAuthenticator.assertionAuthData("example.com", false)[32], 0x19);
        // BE, BS
        Assert.assertEquals(PasskeyAuthenticator.assertionAuthData("example.com", false, false)[32], 0x18);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testRegistrationAuthData() throws Exception {
        Passkey passkey = create();
        byte[] authData = PasskeyAuthenticator.registrationAuthData(passkey, true);
        ByteBuffer buffer = ByteBuffer.wrap(authData);
        byte[] rpIdHash = new byte[32];
        buffer.get(rpIdHash);
        Assert.assertEquals(rpIdHash, PasskeyAuthenticator.sha256("example.com".getBytes(StandardCharsets.US_ASCII)));
        // UP, UV, BE, BS, AT
        Assert.assertEquals(buffer.get(), 0x5d);
        Assert.assertEquals(buffer.getInt(), 0);
        byte[] aaguid = new byte[16];
        buffer.get(aaguid);
        Assert.assertEquals(aaguid, new byte[16]);
        byte[] credentialId = new byte[buffer.getShort()];
        buffer.get(credentialId);
        Assert.assertEquals(credentialId, PasskeyAuthenticator.credentialId(passkey));
        byte[] cose = new byte[buffer.remaining()];
        buffer.get(cose);

        Map<Object, Object> key = (Map<Object, Object>) Cbor.decode(cose);
        Assert.assertEquals(key.get(1L), 2L);
        Assert.assertEquals(key.get(3L), -7L);
        Assert.assertEquals(key.get(-1L), 1L);
        ECPublicKey publicKey = (ECPublicKey) publicKey(passkey);
        Assert.assertEquals((byte[]) key.get(-2L), BigIntegers.asUnsignedByteArray(32, publicKey.getW().getAffineX()));
        Assert.assertEquals((byte[]) key.get(-3L), BigIntegers.asUnsignedByteArray(32, publicKey.getW().getAffineY()));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testAttestationObject() throws Exception {
        byte[] authData = PasskeyAuthenticator.registrationAuthData(create(), false);
        Map<Object, Object> object = (Map<Object, Object>) Cbor.decode(
                PasskeyAuthenticator.attestationObject(authData));
        Assert.assertEquals(object.keySet(), List.of("fmt", "attStmt", "authData"));
        Assert.assertEquals(object.get("fmt"), "none");
        Assert.assertEquals(object.get("attStmt"), Map.of());
        Assert.assertEquals((byte[]) object.get("authData"), authData);
    }

    @Test
    public void testFind() {
        Passkey a = create();
        Passkey b = create();
        Passkey other = PasskeyAuthenticator.create("example.org", new byte[]{1}, "", "", 0);
        List<Passkey> all = List.of(a, other, b);
        Assert.assertEquals(PasskeyAuthenticator.find(all, "example.com", null), List.of(a, b));
        Assert.assertEquals(PasskeyAuthenticator.find(all, "example.com", List.of()), List.of(a, b));
        Assert.assertEquals(PasskeyAuthenticator.find(
                all, "example.com", List.of(PasskeyAuthenticator.credentialId(b), new byte[3])), List.of(b));
        // the credential ID of another relying party
        Assert.assertEquals(PasskeyAuthenticator.find(
                all, "example.com", List.of(PasskeyAuthenticator.credentialId(other))), List.of());
    }

    @Test
    public void testInvalidPrivateKey() {
        Passkey passkey = create();
        passkey.setPrivateKey(PasskeyAuthenticator.base64Url(new byte[32]));
        Assert.assertThrows(IllegalArgumentException.class, () -> PasskeyAuthenticator.cosePublicKey(passkey));
        passkey.setPrivateKey(PasskeyAuthenticator.base64Url(new byte[31]));
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> PasskeyAuthenticator.sign(passkey, new byte[37], new byte[32]));
    }
}
