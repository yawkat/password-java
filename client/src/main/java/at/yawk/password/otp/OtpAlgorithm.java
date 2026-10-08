package at.yawk.password.otp;

/**
 * HMAC algorithm of a TOTP account, named as in the {@code algorithm} parameter of {@code otpauth://} URIs.
 *
 * @author yawkat
 */
public enum OtpAlgorithm {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512");

    final String macName;

    OtpAlgorithm(String macName) {
        this.macName = macName;
    }
}
