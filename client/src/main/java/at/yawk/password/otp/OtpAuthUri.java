package at.yawk.password.otp;

import at.yawk.password.model.OtpAccount;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import lombok.experimental.UtilityClass;

/**
 * The {@code otpauth://} URIs of QR codes and exports (Google's "Key Uri Format"):
 * {@code otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30}.
 *
 * <p>Only {@code totp} is supported. Other types, and Steam codes (which use another alphabet), are rejected rather
 * than read as TOTP codes that would be wrong.
 *
 * @author yawkat
 */
@UtilityClass
public class OtpAuthUri {
    private static final String SCHEME = "otpauth://";
    private static final String HEX = "0123456789ABCDEF";

    /**
     * @throws IllegalArgumentException if the text is not a supported {@code otpauth://} URI, with a message for the
     * user
     */
    public static OtpAccount parse(String uri) {
        String text = uri.trim();
        if (text.regionMatches(true, 0, "otpauth-migration://", 0, "otpauth-migration://".length())) {
            throw new IllegalArgumentException("Google Authenticator exports (otpauth-migration://) are not supported");
        }
        if (!text.regionMatches(true, 0, SCHEME, 0, SCHEME.length())) {
            throw new IllegalArgumentException("Not an otpauth:// URI");
        }
        int typeEnd = text.indexOf('/', SCHEME.length());
        if (typeEnd < 0) {
            throw new IllegalArgumentException("Missing type");
        }
        String type = text.substring(SCHEME.length(), typeEnd).toLowerCase(Locale.ROOT);
        if (!type.equals(OtpAccount.TYPE_TOTP)) {
            throw new IllegalArgumentException("Unsupported type " + type + ", only TOTP is supported");
        }
        int queryStart = text.indexOf('?', typeEnd);
        String label = decode(text.substring(typeEnd + 1, queryStart < 0 ? text.length() : queryStart), false);

        Map<String, String> parameters = new HashMap<>();
        if (queryStart >= 0) {
            for (String parameter : text.substring(queryStart + 1).split("&")) {
                if (parameter.isEmpty()) {
                    continue;
                }
                int eq = parameter.indexOf('=');
                String key = decode(eq < 0 ? parameter : parameter.substring(0, eq), true).toLowerCase(Locale.ROOT);
                String value = eq < 0 ? "" : decode(parameter.substring(eq + 1), true);
                if (parameters.put(key, value) != null) {
                    throw new IllegalArgumentException("Duplicate parameter " + key);
                }
            }
        }

        if ("steam".equalsIgnoreCase(parameters.get("encoder"))) {
            throw new IllegalArgumentException("Steam Guard codes are not supported");
        }

        OtpAccount account = new OtpAccount();
        String issuer = parameters.get("issuer");
        if (issuer != null && label.startsWith(issuer + ":")) {
            // an issuer containing a colon
            label = label.substring(issuer.length() + 1);
        } else {
            int colon = label.indexOf(':');
            if (colon >= 0) {
                if (issuer == null) {
                    issuer = label.substring(0, colon);
                }
                label = label.substring(colon + 1);
            }
        }
        account.setIssuer(issuer == null ? "" : issuer.trim());
        account.setLabel(label.trim());

        String secret = parameters.get("secret");
        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("Missing secret");
        }
        account.setSecret(Base32.normalize(secret));
        String algorithm = parameters.get("algorithm");
        if (algorithm != null) {
            try {
                account.setAlgorithm(OtpAlgorithm.valueOf(algorithm.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Unsupported algorithm " + algorithm);
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
     * @return The URI of the account, for a QR code or an export. Parameters at their default value are left out.
     */
    public static String format(OtpAccount account) {
        Totp.check(account);
        StringBuilder out = new StringBuilder(SCHEME).append(OtpAccount.TYPE_TOTP).append('/');
        if (!account.getIssuer().isEmpty()) {
            out.append(encode(account.getIssuer())).append(':');
        }
        out.append(encode(account.getLabel()));
        out.append("?secret=").append(Base32.normalize(account.getSecret()));
        if (!account.getIssuer().isEmpty()) {
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
            throw new IllegalArgumentException("Invalid " + name + " " + value);
        }
    }

    /**
     * Percent-decoding as UTF-8. Many generators write a space as {@code +} in the query, so it is read as one there.
     */
    private static String decode(String text, boolean query) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '%') {
                int hi = hexDigit(text, i + 1);
                int lo = hexDigit(text, i + 2);
                if (hi < 0 || lo < 0) {
                    throw new IllegalArgumentException("Invalid percent encoding");
                }
                out.write(hi << 4 | lo);
                i += 2;
            } else if (c == '+' && query) {
                out.write(' ');
            } else {
                byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                if (Character.isHighSurrogate(c) && i + 1 < text.length()) {
                    bytes = text.substring(i, i + 2).getBytes(StandardCharsets.UTF_8);
                    i++;
                }
                out.write(bytes, 0, bytes.length);
            }
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
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

    private static int hexDigit(String text, int i) {
        if (i >= text.length()) {
            return -1;
        }
        char c = text.charAt(i);
        // Character.digit would also accept non-ASCII digits
        return c < 128 ? Character.digit(c, 16) : -1;
    }
}
