package at.yawk.password.passkey;

import at.yawk.password.model.Passkey;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class WebAuthnJsonTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void testParseCreationOptions() {
        WebAuthnJson.CreationOptions options = WebAuthnJson.parseCreationOptions(
                "{\"rp\":{\"id\":\"example.com\",\"name\":\"Example\"}," +
                "\"user\":{\"id\":\"AQID\",\"name\":\"alice\",\"displayName\":\"Alice\"}," +
                "\"challenge\":\"BAUG\"," +
                "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-8},{\"type\":\"public-key\",\"alg\":-7}]," +
                "\"excludeCredentials\":[{\"type\":\"public-key\",\"id\":\"BwgJ\"},{\"type\":\"public-key\"}]," +
                "\"authenticatorSelection\":{\"residentKey\":\"required\"}}",
                "fallback.example");
        Assert.assertEquals(options.getRpId(), "example.com");
        Assert.assertEquals(options.getUserId(), new byte[]{1, 2, 3});
        Assert.assertEquals(options.getUserName(), "alice");
        Assert.assertEquals(options.getUserDisplayName(), "Alice");
        Assert.assertEquals(options.getChallenge(), new byte[]{4, 5, 6});
        Assert.assertTrue(options.isEs256());
        Assert.assertEquals(options.getExcludeCredentials().size(), 1);
        Assert.assertEquals(options.getExcludeCredentials().get(0), new byte[]{7, 8, 9});
    }

    @Test
    public void testParseCreationOptionsDefaults() {
        WebAuthnJson.CreationOptions options = WebAuthnJson.parseCreationOptions(
                "{\"rp\":{},\"user\":{\"id\":\"AQ\"},\"challenge\":\"AA\"," +
                "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-257}]}",
                "example.com");
        Assert.assertEquals(options.getRpId(), "example.com");
        Assert.assertEquals(options.getUserName(), "");
        Assert.assertFalse(options.isEs256());
        Assert.assertTrue(options.getExcludeCredentials().isEmpty());
    }

    @Test
    public void testParseCreationOptionsDefaultAlgorithms() {
        // no pubKeyCredParams, or an empty list, mean ES256 and RS256
        Assert.assertTrue(WebAuthnJson.parseCreationOptions(
                "{\"rp\":{},\"user\":{\"id\":\"AQ\"},\"challenge\":\"AA\"}", "example.com").isEs256());
        Assert.assertTrue(WebAuthnJson.parseCreationOptions(
                "{\"rp\":{},\"user\":{\"id\":\"AQ\"},\"challenge\":\"AA\",\"pubKeyCredParams\":[]}",
                "example.com").isEs256());
    }

    @Test
    public void testParseInvalid() {
        Assert.assertThrows(IllegalArgumentException.class, () -> WebAuthnJson.parseCreationOptions("[", null));
        Assert.assertThrows(IllegalArgumentException.class, () -> WebAuthnJson.parseCreationOptions("[]", null));
        // no rp id
        Assert.assertThrows(IllegalArgumentException.class, () -> WebAuthnJson.parseCreationOptions(
                "{\"user\":{\"id\":\"AQ\"},\"challenge\":\"AA\"}", null));
        // no user id
        Assert.assertThrows(IllegalArgumentException.class, () -> WebAuthnJson.parseCreationOptions(
                "{\"rp\":{\"id\":\"a\"},\"challenge\":\"AA\"}", null));
        // not base64url
        Assert.assertThrows(IllegalArgumentException.class, () -> WebAuthnJson.parseRequestOptions(
                "{\"rpId\":\"a\",\"challenge\":\"*\"}", null));
        Assert.assertThrows(IllegalArgumentException.class, () -> WebAuthnJson.parseRequestOptions(
                "{\"challenge\":\"AA\"}", null));
    }

    @Test
    public void testParseRequestOptions() {
        WebAuthnJson.RequestOptions options = WebAuthnJson.parseRequestOptions(
                "{\"rpId\":\"example.com\",\"challenge\":\"BAUG\",\"userVerification\":\"preferred\"," +
                "\"allowCredentials\":[{\"type\":\"public-key\",\"id\":\"BwgJ\",\"transports\":[\"internal\"]}]}",
                null);
        Assert.assertEquals(options.getRpId(), "example.com");
        Assert.assertEquals(options.getChallenge(), new byte[]{4, 5, 6});
        Assert.assertEquals(options.getAllowCredentials().size(), 1);
        Assert.assertEquals(options.getAllowCredentials().get(0), new byte[]{7, 8, 9});

        options = WebAuthnJson.parseRequestOptions("{\"challenge\":\"BAUG\"}", "example.org");
        Assert.assertEquals(options.getRpId(), "example.org");
        Assert.assertTrue(options.getAllowCredentials().isEmpty());
    }

    @Test
    public void testClientDataJson() throws Exception {
        JsonNode node = MAPPER.readTree(WebAuthnJson.clientDataJson(
                "webauthn.get", new byte[]{(byte) 0xfb, (byte) 0xff}, "https://example.com", "com.example"));
        Assert.assertEquals(node.toString(),
                            "{\"type\":\"webauthn.get\",\"challenge\":\"-_8\",\"origin\":\"https://example.com\"," +
                            "\"crossOrigin\":false,\"androidPackageName\":\"com.example\"}");
        Assert.assertFalse(new String(WebAuthnJson.clientDataJson(
                "webauthn.get", new byte[1], "https://example.com", null), StandardCharsets.UTF_8)
                                   .contains("androidPackageName"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testRegistrationResponse() throws Exception {
        Passkey passkey = PasskeyAuthenticator.create("example.com", new byte[]{1}, "alice", "", 0);
        byte[] clientData = WebAuthnJson.clientDataJson("webauthn.create", new byte[]{1}, "https://example.com", null);
        byte[] authData = PasskeyAuthenticator.registrationAuthData(passkey, true);
        JsonNode node = MAPPER.readTree(WebAuthnJson.registrationResponse(passkey, clientData, authData));
        Assert.assertEquals(node.path("id").asText(), passkey.getCredentialId());
        Assert.assertEquals(node.path("rawId").asText(), passkey.getCredentialId());
        Assert.assertEquals(node.path("type").asText(), "public-key");
        JsonNode response = node.path("response");
        Assert.assertEquals(PasskeyAuthenticator.fromBase64Url(response.path("clientDataJSON").asText()), clientData);
        Assert.assertEquals(PasskeyAuthenticator.fromBase64Url(response.path("authenticatorData").asText()), authData);
        Map<Object, Object> attestation = (Map<Object, Object>) Cbor.decode(
                PasskeyAuthenticator.fromBase64Url(response.path("attestationObject").asText()));
        Assert.assertEquals((byte[]) attestation.get("authData"), authData);
        Assert.assertEquals(response.path("publicKeyAlgorithm").asLong(), -7);
        KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(
                PasskeyAuthenticator.fromBase64Url(response.path("publicKey").asText())));
        Assert.assertTrue(node.path("clientExtensionResults").path("credProps").path("rk").asBoolean());
    }

    @Test
    public void testAssertionResponse() throws Exception {
        Passkey passkey = PasskeyAuthenticator.create("example.com", new byte[]{1, 2}, "alice", "", 0);
        byte[] clientData = WebAuthnJson.clientDataJson("webauthn.get", new byte[]{1}, "https://example.com", null);
        byte[] authData = PasskeyAuthenticator.assertionAuthData("example.com", true);
        byte[] signature = PasskeyAuthenticator.sign(passkey, authData, PasskeyAuthenticator.sha256(clientData));
        JsonNode node = MAPPER.readTree(WebAuthnJson.assertionResponse(passkey, clientData, authData, signature));
        Assert.assertEquals(node.path("id").asText(), passkey.getCredentialId());
        JsonNode response = node.path("response");
        Assert.assertEquals(response.path("userHandle").asText(), "AQI");

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(PasskeyAuthenticator.spkiPublicKey(passkey))));
        verifier.update(PasskeyAuthenticator.fromBase64Url(response.path("authenticatorData").asText()));
        verifier.update(PasskeyAuthenticator.sha256(
                PasskeyAuthenticator.fromBase64Url(response.path("clientDataJSON").asText())));
        Assert.assertTrue(verifier.verify(PasskeyAuthenticator.fromBase64Url(response.path("signature").asText())));
    }

    @Test
    public void testOriginMatchesRpId() {
        Assert.assertTrue(WebAuthnJson.originMatchesRpId("https://example.com", "example.com"));
        Assert.assertTrue(WebAuthnJson.originMatchesRpId("https://Example.COM:8443", "example.com"));
        Assert.assertTrue(WebAuthnJson.originMatchesRpId("https://login.example.com", "example.com"));
        Assert.assertTrue(WebAuthnJson.originMatchesRpId("http://localhost:8080", "localhost"));
        Assert.assertFalse(WebAuthnJson.originMatchesRpId("http://example.com", "example.com"));
        Assert.assertFalse(WebAuthnJson.originMatchesRpId("https://example.com", "login.example.com"));
        Assert.assertFalse(WebAuthnJson.originMatchesRpId("https://badexample.com", "example.com"));
        Assert.assertFalse(WebAuthnJson.originMatchesRpId("https://example.com", "com"));
        Assert.assertFalse(WebAuthnJson.originMatchesRpId("https://1.2.3.4", "2.3.4"));
        Assert.assertTrue(WebAuthnJson.originMatchesRpId("https://1.2.3.4", "1.2.3.4"));
        Assert.assertFalse(WebAuthnJson.originMatchesRpId("android:apk-key-hash:abc", "example.com"));
        Assert.assertFalse(WebAuthnJson.originMatchesRpId("https://user@example.com", "example.com"));
        Assert.assertFalse(WebAuthnJson.originMatchesRpId("not a uri", "example.com"));
    }
}
