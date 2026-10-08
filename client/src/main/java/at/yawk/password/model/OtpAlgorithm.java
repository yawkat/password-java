package at.yawk.password.model;

/**
 * HMAC algorithm of a TOTP account, named as in the {@code algorithm} parameter of {@code otpauth://} URIs. Stored in
 * the vault by name.
 *
 * @author yawkat
 */
public enum OtpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}
