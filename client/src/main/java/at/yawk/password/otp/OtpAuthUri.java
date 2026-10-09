package at.yawk.password.otp;

import at.yawk.password.AuthProtocol;
import at.yawk.password.model.OtpAccount;
import at.yawk.password.model.OtpAlgorithm;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import lombok.experimental.UtilityClass;

/**
 * The {@code otpauth://} URIs of QR codes and exports (Google's "Key Uri Format"):
 * {@code otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30}.
 *
 * <p>Only {@code totp} is supported. Other types, Steam codes (which use another alphabet), and URIs that look
 * mangled (e.g. HTML-escaped) are rejected rather than read as an account that gives wrong codes. Error messages
 * never contain parts of the URI except the names of known parameters, since any part may hold the secret.
 *
 * @author yawkat
 */
@UtilityClass
public class OtpAuthUri {
    private static final String SCHEME = "otpauth://";
    private static final String HEX = "0123456789ABCDEF";
    private static final Set<String> KNOWN_PARAMETERS =
            Set.of("secret", "issuer", "algorithm", "digits", "period", "counter", "encoder", "image");

    /**
     * @throws IllegalArgumentException if the text is not a supported {@code otpauth://} URI, with a message for the
     * user
     */
    public static OtpAccount parse(String uri) {
        // '#' is not a fragment separator: a URI with a raw '#' in it is either rejected (in a number or the secret)
        // or keeps it in the issuer or label, rather than silently dropping the parameters after it
        String text = uri.trim();
        if (text.regionMatches(true, 0, "otpauth-migration://", 0, "otpauth-migration://".length())) {
            throw new IllegalArgumentException("Google Authenticator exports (otpauth-migration://) are not supported");
        }
        if (!text.regionMatches(true, 0, SCHEME, 0, SCHEME.length())) {
            throw new IllegalArgumentException("Not an otpauth:// URI");
        }
        if (text.toLowerCase(Locale.ROOT).indexOf(SCHEME, SCHEME.length()) >= 0) {
            throw new IllegalArgumentException("More than one otpauth:// URI");
        }
        int typeEnd = SCHEME.length();
        while (typeEnd < text.length() && text.charAt(typeEnd) != '/' && text.charAt(typeEnd) != '?') {
            typeEnd++;
        }
        if (typeEnd == text.length() || text.charAt(typeEnd) != '/') {
            throw new IllegalArgumentException("Missing type or label");
        }
        String type = text.substring(SCHEME.length(), typeEnd).toLowerCase(Locale.ROOT);
        if (!type.equals(OtpAccount.TYPE_TOTP)) {
            throw new IllegalArgumentException(
                    (type.equals("hotp") || type.equals("steam") ? "Unsupported type " + type : "Unsupported type") +
                    ", only TOTP is supported");
        }
        int queryStart = text.indexOf('?', typeEnd);
        String label = decode(text.substring(typeEnd + 1, queryStart < 0 ? text.length() : queryStart), false);

        Map<String, String> parameters = new HashMap<>();
        if (queryStart >= 0) {
            String query = text.substring(queryStart + 1);
            if (query.indexOf(';') >= 0) {
                // "&amp;" of HTML, or ';' as a separator: the parameters after it would be lost
                throw new IllegalArgumentException("Malformed parameters (';' in the query)");
            }
            for (String parameter : query.split("&")) {
                if (parameter.isEmpty()) {
                    continue;
                }
                int eq = parameter.indexOf('=');
                String key = decode(eq < 0 ? parameter : parameter.substring(0, eq), true).toLowerCase(Locale.ROOT);
                String value = eq < 0 ? "" : decode(parameter.substring(eq + 1), true);
                if (parameters.put(key, value) != null) {
                    throw new IllegalArgumentException(KNOWN_PARAMETERS.contains(key) ?
                                                               "Duplicate parameter " + key : "Duplicate parameter");
                }
            }
        }

        if ("steam".equalsIgnoreCase(parameters.get("encoder"))) {
            throw new IllegalArgumentException("Steam Guard codes are not supported");
        }

        OtpAccount account = new OtpAccount();
        // The label is "issuer:account" or "account", optionally with spaces around the colon. An explicitly empty
        // issuer parameter means that there is no issuer, so a colon in the label is part of the account (this is how
        // format writes such a label).
        String issuer = parameters.containsKey("issuer") ? parameters.get("issuer").trim() : null;
        if (issuer == null || !issuer.isEmpty()) {
            int colon = issuer == null ? -1 : issuerPrefixEnd(label, issuer);
            if (colon < 0) {
                colon = label.indexOf(':');
            }
            if (colon >= 0) {
                if (issuer == null) {
                    issuer = label.substring(0, colon);
                }
                label = label.substring(colon + 1);
            }
        }
        account.setIssuer(issuer);
        account.setLabel(label);

        String secret = parameters.get("secret");
        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("Missing secret");
        }
        account.setSecret(secret);
        String algorithm = parameters.get("algorithm");
        if (algorithm != null) {
            try {
                account.setAlgorithm(OtpAlgorithm.valueOf(algorithm.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Unsupported algorithm");
            }
        }
        if (parameters.containsKey("digits")) {
            account.setDigits(parseInt(parameters.get("digits"), "digits"));
        }
        if (parameters.containsKey("period")) {
            account.setPeriod(parseInt(parameters.get("period"), "period"));
        }
        Totp.check(account);
        return account;
    }

    /**
     * @return The index of the colon after the issuer at the start of the label, or -1
     */
    private static int issuerPrefixEnd(String label, String issuer) {
        if (!label.startsWith(issuer)) {
            return -1;
        }
        int i = issuer.length();
        while (i < label.length() && label.charAt(i) == ' ') {
            i++;
        }
        return i < label.length() && label.charAt(i) == ':' ? i : -1;
    }

    /**
     * @return The URI of the account, for a QR code or an export. Parameters at their default value are left out.
     */
    public static String format(OtpAccount account) {
        Totp.check(account);
        StringBuilder out = new StringBuilder(SCHEME).append(OtpAccount.TYPE_TOTP).append('/');
        if (!account.getIssuer().isEmpty()) {
            out.append(encode(account.getIssuer())).append(':');
        }
        out.append(encode(account.getLabel()));
        out.append("?secret=").append(account.getSecret());
        if (!account.getIssuer().isEmpty() || account.getLabel().indexOf(':') >= 0) {
            // an empty issuer keeps parse from splitting a colon in the label
            out.append("&issuer=").append(encode(account.getIssuer()));
        }
        if (account.getAlgorithm() != OtpAlgorithm.SHA1) {
            out.append("&algorithm=").append(account.getAlgorithm().name());
        }
        if (account.getDigits() != 6) {
            out.append("&digits=").append(account.getDigits());
        }
        if (account.getPeriod() != 30) {
            out.append("&period=").append(account.getPeriod());
        }
        return out.toString();
    }

    private static int parseInt(String value, String name) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid " + name);
        }
    }

    /**
     * Percent-decoding as UTF-8. Many generators write a space as {@code +} in the query, so it is read as one there.
     */
    private static String decode(String text, boolean query) {
        StringBuilder out = new StringBuilder(text.length());
        ByteArrayOutputStream escaped = new ByteArrayOutputStream();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '%') {
                int hi = i + 1 < text.length() ? AuthProtocol.hexDigit(text.charAt(i + 1)) : -1;
                int lo = i + 2 < text.length() ? AuthProtocol.hexDigit(text.charAt(i + 2)) : -1;
                if (hi < 0 || lo < 0) {
                    throw new IllegalArgumentException("Invalid percent encoding");
                }
                escaped.write(hi << 4 | lo);
                i += 2;
                continue;
            }
            flushUtf8(escaped, out);
            out.append(c == '+' && query ? ' ' : c);
        }
        flushUtf8(escaped, out);
        return out.toString();
    }

    /**
     * Decode a run of percent escapes, rejecting invalid UTF-8 rather than replacing it.
     */
    private static void flushUtf8(ByteArrayOutputStream escaped, StringBuilder out) {
        if (escaped.size() == 0) {
            return;
        }
        try {
            out.append(StandardCharsets.UTF_8.newDecoder()
                               .onMalformedInput(CodingErrorAction.REPORT)
                               .onUnmappableCharacter(CodingErrorAction.REPORT)
                               .decode(ByteBuffer.wrap(escaped.toByteArray())));
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Invalid UTF-8 in percent encoding");
        }
        escaped.reset();
    }

    private static String encode(String text) {
        StringBuilder out = new StringBuilder();
        for (byte b : text.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
                c == '-' || c == '.' || c == '_' || c == '~') {
                out.append((char) c);
            } else {
                out.append('%').append(HEX.charAt(c >> 4)).append(HEX.charAt(c & 0xf));
            }
        }
        return out.toString();
    }
}
