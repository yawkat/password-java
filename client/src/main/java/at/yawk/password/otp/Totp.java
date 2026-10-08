package at.yawk.password.otp;

import at.yawk.password.model.OtpAccount;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.experimental.UtilityClass;

/**
 * Time-based one-time passwords (RFC 6238): HOTP (RFC 4226) of the number of {@code period}-second steps since the
 * epoch.
 *
 * <p>Besides the usual 6 digits every 30 s this covers other parameters, e.g. the tokens of sites that used Authy's
 * API directly (Cloudflare and others: 7 digits every 10 s).
 *
 * @author yawkat
 */
@UtilityClass
public class Totp {
    public static final int MIN_DIGITS = 6;
    /**
     * HOTP truncates to 31 bits, so more than 10 digits would only add leading zeros.
     */
    public static final int MAX_DIGITS = 10;

    /**
     * @return The code of the account at the given time
     * @throws IllegalArgumentException if the account is not a valid TOTP account
     */
    public static String code(OtpAccount account, long unixMillis) {
        check(account);
        byte[] secret = Base32.decode(account.getSecret());
        try {
            return code(secret, account.getAlgorithm(), account.getDigits(), account.getPeriod(),
                        Math.floorDiv(unixMillis, 1000));
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    /**
     * @return Milliseconds until the code of the account changes
     */
    public static long millisUntilNext(OtpAccount account, long unixMillis) {
        if (account.getPeriod() <= 0) {
            throw new IllegalArgumentException("Invalid period " + account.getPeriod());
        }
        long periodMillis = account.getPeriod() * 1000L;
        return periodMillis - Math.floorMod(unixMillis, periodMillis);
    }

    static String code(byte[] secret, OtpAlgorithm algorithm, int digits, long periodSeconds, long unixSeconds) {
        if (digits < MIN_DIGITS || digits > MAX_DIGITS || periodSeconds <= 0) {
            throw new IllegalArgumentException("Invalid TOTP parameters");
        }
        long counter = Math.floorDiv(unixSeconds, periodSeconds);
        byte[] hash;
        try {
            Mac mac = Mac.getInstance(algorithm.macName);
            mac.init(new SecretKeySpec(secret, algorithm.macName));
            hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        int offset = hash[hash.length - 1] & 0xf;
        long binary = ByteBuffer.wrap(hash, offset, 4).getInt() & 0x7fffffffL;
        Arrays.fill(hash, (byte) 0);
        long modulus = 1;
        for (int i = 0; i < digits; i++) {
            modulus *= 10;
        }
        StringBuilder code = new StringBuilder(Long.toString(binary % modulus));
        while (code.length() < digits) {
            code.insert(0, '0');
        }
        return code.toString();
    }

    /**
     * @throws IllegalArgumentException if the account can't generate codes
     */
    public static void check(OtpAccount account) {
        if (!OtpAccount.TYPE_TOTP.equals(account.getType())) {
            throw new IllegalArgumentException("Unsupported type " + account.getType() + ", only TOTP is supported");
        }
        if (account.getAlgorithm() == null) {
            throw new IllegalArgumentException("Missing algorithm");
        }
        if (account.getDigits() < MIN_DIGITS || account.getDigits() > MAX_DIGITS) {
            throw new IllegalArgumentException("Unsupported number of digits " + account.getDigits() + ", must be " +
                                               MIN_DIGITS + " to " + MAX_DIGITS);
        }
        if (account.getPeriod() <= 0) {
            throw new IllegalArgumentException("Invalid period " + account.getPeriod());
        }
        if (account.getSecret() == null) {
            throw new IllegalArgumentException("Missing secret");
        }
        byte[] secret = Base32.decode(account.getSecret());
        Arrays.fill(secret, (byte) 0);
        if (secret.length == 0) {
            throw new IllegalArgumentException("Missing secret");
        }
    }
}
