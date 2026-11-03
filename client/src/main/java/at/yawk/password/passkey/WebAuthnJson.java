package at.yawk.password.passkey;

import at.yawk.password.model.Passkey;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import lombok.Value;
import org.jetbrains.annotations.Nullable;

/**
 * The JSON forms of WebAuthn requests and responses (WebAuthn Level 3, {@code parseCreationOptionsFromJSON} and
 * {@code toJSON}), which Android's Credential Manager passes to and expects from a credential provider.
 *
 * @author yawkat
 */
public final class WebAuthnJson {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private WebAuthnJson() {
    }

    /**
     * The parts of {@code PublicKeyCredentialCreationOptions} that we use.
     */
    @Value
    public static class CreationOptions {
        String rpId;
        byte[] userId;
        String userName;
        String userDisplayName;
        byte[] challenge;
        /**
         * Whether the relying party accepts ES256, the only algorithm we can create.
         */
        boolean es256;
        List<byte[]> excludeCredentials;
    }

    /**
     * The parts of {@code PublicKeyCredentialRequestOptions} that we use.
     */
    @Value
    public static class RequestOptions {
        String rpId;
        byte[] challenge;
        /**
         * Empty for a discoverable credential request.
         */
        List<byte[]> allowCredentials;
    }

    /**
     * @param defaultRpId The relying party ID to use if the options have none: the host of the origin
     * @throws IllegalArgumentException if the JSON is invalid or misses required fields
     */
    public static CreationOptions parseCreationOptions(String json, @Nullable String defaultRpId) {
        JsonNode root = parse(json);
        JsonNode rp = root.path("rp");
        String rpId = rp.path("id").isTextual() ? rp.path("id").asText() : defaultRpId;
        if (rpId == null || rpId.isEmpty()) {
            throw new IllegalArgumentException("Missing rp.id");
        }
        JsonNode user = root.path("user");
        JsonNode params = root.path("pubKeyCredParams");
        // no parameters mean the defaults, ES256 and RS256
        boolean es256 = params.isEmpty();
        for (JsonNode param : params) {
            if (param.path("type").asText("public-key").equals("public-key") &&
                param.path("alg").canConvertToLong() &&
                param.path("alg").asLong() == PasskeyAuthenticator.COSE_ES256) {
                es256 = true;
            }
        }
        return new CreationOptions(
                rpId,
                requiredBytes(user, "id"),
                user.path("name").asText(""),
                user.path("displayName").asText(""),
                requiredBytes(root, "challenge"),
                es256,
                credentialIds(root.path("excludeCredentials"))
        );
    }

    /**
     * @param defaultRpId The relying party ID to use if the options have none: the host of the origin
     * @throws IllegalArgumentException if the JSON is invalid or misses required fields
     */
    public static RequestOptions parseRequestOptions(String json, @Nullable String defaultRpId) {
        JsonNode root = parse(json);
        String rpId = root.path("rpId").isTextual() ? root.path("rpId").asText() : defaultRpId;
        if (rpId == null || rpId.isEmpty()) {
            throw new IllegalArgumentException("Missing rpId");
        }
        return new RequestOptions(rpId, requiredBytes(root, "challenge"), credentialIds(root.path("allowCredentials")));
    }

    private static JsonNode parse(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            if (root == null || !root.isObject()) {
                throw new IllegalArgumentException("Not a JSON object");
            }
            return root;
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid JSON", e);
        }
    }

    private static byte[] requiredBytes(JsonNode parent, String field) {
        JsonNode node = parent.path(field);
        if (!node.isTextual()) {
            throw new IllegalArgumentException("Missing " + field);
        }
        return PasskeyAuthenticator.fromBase64Url(node.asText());
    }

    private static List<byte[]> credentialIds(JsonNode descriptors) {
        List<byte[]> ids = new ArrayList<>();
        for (JsonNode descriptor : descriptors) {
            if (descriptor.path("type").asText("public-key").equals("public-key") && descriptor.path("id").isTextual()) {
                try {
                    ids.add(PasskeyAuthenticator.fromBase64Url(descriptor.path("id").asText()));
                } catch (IllegalArgumentException ignored) {
                    // not one of ours, whatever it is
                }
            }
        }
        return ids;
    }

    /**
     * The {@code clientDataJSON} of a request, which the authenticator signs (through its hash). A browser computes it
     * itself and passes only the hash; for an app, the provider makes it.
     *
     * @param type               {@code webauthn.create} or {@code webauthn.get}
     * @param androidPackageName The package of the calling app, or {@code null}
     */
    public static byte[] clientDataJson(String type, byte[] challenge, String origin,
                                        @Nullable String androidPackageName) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("type", type);
        node.put("challenge", PasskeyAuthenticator.base64Url(challenge));
        node.put("origin", origin);
        node.put("crossOrigin", false);
        if (androidPackageName != null) {
            node.put("androidPackageName", androidPackageName);
        }
        return node.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * {@code RegistrationResponseJSON} for a passkey we just created.
     */
    public static String registrationResponse(Passkey passkey, byte[] clientDataJson, byte[] authData) {
        ObjectNode response = MAPPER.createObjectNode();
        response.put("clientDataJSON", PasskeyAuthenticator.base64Url(clientDataJson));
        response.put("attestationObject",
                     PasskeyAuthenticator.base64Url(PasskeyAuthenticator.attestationObject(authData)));
        ArrayNode transports = response.putArray("transports");
        transports.add("internal");
        transports.add("hybrid");
        response.put("authenticatorData", PasskeyAuthenticator.base64Url(authData));
        response.put("publicKeyAlgorithm", PasskeyAuthenticator.COSE_ES256);
        response.put("publicKey", PasskeyAuthenticator.base64Url(PasskeyAuthenticator.spkiPublicKey(passkey)));
        ObjectNode root = credential(passkey);
        root.set("response", response);
        root.putObject("clientExtensionResults").putObject("credProps").put("rk", true);
        return root.toString();
    }

    /**
     * {@code AuthenticationResponseJSON} for signing in with {@code passkey}.
     */
    public static String assertionResponse(Passkey passkey, byte[] clientDataJson, byte[] authData, byte[] signature) {
        ObjectNode response = MAPPER.createObjectNode();
        response.put("clientDataJSON", PasskeyAuthenticator.base64Url(clientDataJson));
        response.put("authenticatorData", PasskeyAuthenticator.base64Url(authData));
        response.put("signature", PasskeyAuthenticator.base64Url(signature));
        response.put("userHandle", passkey.getUserHandle());
        ObjectNode root = credential(passkey);
        root.set("response", response);
        root.putObject("clientExtensionResults");
        return root.toString();
    }

    private static ObjectNode credential(Passkey passkey) {
        ObjectNode root = MAPPER.createObjectNode();
        // normalized, in case another client stored it with padding
        String id = PasskeyAuthenticator.base64Url(PasskeyAuthenticator.credentialId(passkey));
        root.put("id", id);
        root.put("rawId", id);
        root.put("type", "public-key");
        root.put("authenticatorAttachment", "platform");
        return root;
    }

    /**
     * The host of a web origin, lower case, or {@code null} if it is not a secure web origin ({@code https}, or
     * {@code http} on {@code localhost}).
     */
    @Nullable
    public static String webOriginHost(String origin) {
        URI uri;
        try {
            uri = new URI(origin);
        } catch (URISyntaxException e) {
            return null;
        }
        String host = uri.getHost();
        if (host == null || uri.getRawUserInfo() != null) {
            return null;
        }
        host = host.toLowerCase(Locale.ROOT);
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            return host;
        }
        if ("http".equalsIgnoreCase(uri.getScheme()) && host.equals("localhost")) {
            return host;
        }
        return null;
    }

    /**
     * Whether a web page at {@code origin} may use passkeys of {@code rpId}: the relying party ID must be the host of
     * the origin or a parent domain of it (WebAuthn's "registrable domain suffix"). Without the public suffix list, a
     * parent domain is only accepted if it has a dot, so {@code com} is refused but {@code co.uk} is not; the browser
     * has checked this already.
     */
    public static boolean originMatchesRpId(String origin, String rpId) {
        String host = webOriginHost(origin);
        if (host == null) {
            return false;
        }
        String id = rpId.toLowerCase(Locale.ROOT);
        if (host.equals(id)) {
            return true;
        }
        return id.contains(".") && host.endsWith("." + id) && !isIpAddress(host);
    }

    private static boolean isIpAddress(String host) {
        return host.startsWith("[") || host.matches("[0-9.]+");
    }
}
