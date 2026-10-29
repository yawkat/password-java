package at.yawk.password.passkey;

import at.yawk.password.HashUtil;
import at.yawk.password.model.Passkey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.jetbrains.annotations.Nullable;

/**
 * The authenticator side of WebAuthn for the passkeys of the vault, shared by the Android credential provider and the
 * desktop security key: creating a passkey, and the authenticator data, attestation and signatures that a relying
 * party checks.
 *
 * <p>Passkeys are ES256 only, the one algorithm every relying party supports. They are synced, so the signature
 * counter is always 0 (which tells relying parties not to check it) and the backup flags are set. Attestation is
 * {@code none}, with an all-zero AAGUID.
 *
 * @author yawkat
 */
public final class PasskeyAuthenticator {
    /**
     * COSE algorithm identifier of ES256.
     */
    public static final long COSE_ES256 = -7;
    /**
     * We make no claim about the make of the authenticator.
     */
    public static final byte[] AAGUID = new byte[16];

    static final int FLAG_UP = 0x01;
    static final int FLAG_UV = 0x04;
    static final int FLAG_BE = 0x08;
    static final int FLAG_BS = 0x10;
    static final int FLAG_AT = 0x40;

    static final int CREDENTIAL_ID_LENGTH = 32;
    private static final int PRIVATE_KEY_LENGTH = 32;

    private static final ECNamedDomainParameters P256;

    static {
        X9ECParameters curve = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
        P256 = new ECNamedDomainParameters(SECObjectIdentifiers.secp256r1, curve);
    }

    private PasskeyAuthenticator() {
    }

    /**
     * Create a new passkey with a random key pair and credential ID.
     *
     * @param userHandle {@code user.id} of the relying party, 1 to 64 bytes
     * @param now        Creation time, milliseconds since the epoch
     */
    public static Passkey create(String rpId, byte[] userHandle, String userName, String userDisplayName, long now) {
        if (rpId.isEmpty()) {
            throw new IllegalArgumentException("Empty relying party ID");
        }
        if (userHandle.length == 0 || userHandle.length > 64) {
            throw new IllegalArgumentException("Invalid user handle length");
        }
        BigInteger d;
        do {
            d = BigIntegers.fromUnsignedByteArray(HashUtil.generateRandomBytes(PRIVATE_KEY_LENGTH));
        } while (d.signum() == 0 || d.compareTo(P256.getN()) >= 0);
        Passkey passkey = new Passkey();
        passkey.setRpId(rpId);
        passkey.setCredentialId(base64Url(HashUtil.generateRandomBytes(CREDENTIAL_ID_LENGTH)));
        passkey.setUserHandle(base64Url(userHandle));
        passkey.setUserName(userName);
        passkey.setUserDisplayName(userDisplayName);
        passkey.setPrivateKey(base64Url(BigIntegers.asUnsignedByteArray(PRIVATE_KEY_LENGTH, d)));
        passkey.setCreated(now);
        return passkey;
    }

    /**
     * The passkeys of {@code passkeys} for the relying party, in the order given.
     *
     * @param allowList Credential IDs that the relying party accepts, or {@code null} or empty for any (a discoverable
     *                  credential request)
     */
    public static List<Passkey> find(Collection<Passkey> passkeys, String rpId, @Nullable Collection<byte[]> allowList) {
        List<Passkey> found = new ArrayList<>();
        for (Passkey passkey : passkeys) {
            if (!passkey.getRpId().equals(rpId)) {
                continue;
            }
            if (allowList != null && !allowList.isEmpty()) {
                byte[] id = credentialId(passkey);
                if (allowList.stream().noneMatch(allowed -> Arrays.equals(allowed, id))) {
                    continue;
                }
            }
            found.add(passkey);
        }
        return found;
    }

    /**
     * Authenticator data for creating {@code passkey}: with the attested credential data (AAGUID, credential ID and
     * public key).
     */
    public static byte[] registrationAuthData(Passkey passkey, boolean userVerified) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeAuthDataHeader(out, passkey.getRpId(), flags(userVerified) | FLAG_AT);
        out.write(AAGUID, 0, AAGUID.length);
        byte[] credentialId = credentialId(passkey);
        out.write(credentialId.length >> 8);
        out.write(credentialId.length);
        out.write(credentialId, 0, credentialId.length);
        byte[] publicKey = cosePublicKey(passkey);
        out.write(publicKey, 0, publicKey.length);
        return out.toByteArray();
    }

    /**
     * Authenticator data for signing in, after the user agreed.
     */
    public static byte[] assertionAuthData(String rpId, boolean userVerified) {
        return assertionAuthData(rpId, true, userVerified);
    }

    /**
     * Authenticator data for signing in.
     *
     * @param userPresent Whether the user agreed. Only a security key's "silent" requests, which a browser uses to
     *                    find out whether a credential is there, are answered without asking.
     */
    public static byte[] assertionAuthData(String rpId, boolean userPresent, boolean userVerified) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeAuthDataHeader(out, rpId, flags(userVerified) & (userPresent ? 0xff : ~FLAG_UP));
        return out.toByteArray();
    }

    private static int flags(boolean userVerified) {
        // Passkeys are synced, so eligible for backup and backed up
        return FLAG_UP | FLAG_BE | FLAG_BS | (userVerified ? FLAG_UV : 0);
    }

    private static void writeAuthDataHeader(ByteArrayOutputStream out, String rpId, int flags) {
        byte[] rpIdHash = sha256(rpId.getBytes(StandardCharsets.UTF_8));
        out.write(rpIdHash, 0, rpIdHash.length);
        out.write(flags);
        // signature counter: always 0
        out.write(0);
        out.write(0);
        out.write(0);
        out.write(0);
    }

    /**
     * The attestation object for {@code authData} without attestation (format {@code none}).
     */
    public static byte[] attestationObject(byte[] authData) {
        Map<String, Object> object = new LinkedHashMap<>();
        object.put("fmt", "none");
        object.put("attStmt", Map.of());
        object.put("authData", authData);
        return Cbor.encode(object);
    }

    /**
     * The ES256 signature (ASN.1 DER) over {@code authData ‖ clientDataHash}. Deterministic (RFC 6979), so it does not
     * depend on the quality of the random number generator.
     */
    public static byte[] sign(Passkey passkey, byte[] authData, byte[] clientDataHash) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(privateScalar(passkey), P256));
        BigInteger[] rs = signer.generateSignature(sha256(authData, clientDataHash));
        try {
            return new DERSequence(new ASN1Integer[]{new ASN1Integer(rs[0]), new ASN1Integer(rs[1])}).getEncoded();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * The public key as a COSE_Key (RFC 9053): EC2, P-256, ES256.
     */
    public static byte[] cosePublicKey(Passkey passkey) {
        ECPoint q = publicPoint(passkey);
        Map<Long, Object> key = new LinkedHashMap<>();
        key.put(1L, 2L); // kty: EC2
        key.put(3L, COSE_ES256); // alg
        key.put(-1L, 1L); // crv: P-256
        key.put(-2L, BigIntegers.asUnsignedByteArray(32, q.getAffineXCoord().toBigInteger()));
        key.put(-3L, BigIntegers.asUnsignedByteArray(32, q.getAffineYCoord().toBigInteger()));
        return Cbor.encode(key);
    }

    /**
     * The public key as an X.509 SubjectPublicKeyInfo (DER), as WebAuthn's {@code getPublicKey()} returns it.
     */
    public static byte[] spkiPublicKey(Passkey passkey) {
        try {
            return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
                    new ECPublicKeyParameters(publicPoint(passkey), P256)).getEncoded();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static ECPoint publicPoint(Passkey passkey) {
        return P256.getG().multiply(privateScalar(passkey)).normalize();
    }

    private static BigInteger privateScalar(Passkey passkey) {
        byte[] bytes = fromBase64Url(passkey.getPrivateKey());
        BigInteger d = BigIntegers.fromUnsignedByteArray(bytes);
        Arrays.fill(bytes, (byte) 0);
        if (bytes.length != PRIVATE_KEY_LENGTH || d.signum() == 0 || d.compareTo(P256.getN()) >= 0) {
            throw new IllegalArgumentException("Invalid private key");
        }
        return d;
    }

    public static byte[] credentialId(Passkey passkey) {
        return fromBase64Url(passkey.getCredentialId());
    }

    public static byte[] userHandle(Passkey passkey) {
        return fromBase64Url(passkey.getUserHandle());
    }

    public static byte[] sha256(byte[]... parts) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
        for (byte[] part : parts) {
            digest.update(part);
        }
        return digest.digest();
    }

    public static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Decodes base64url with or without padding.
     *
     * @throws IllegalArgumentException if the text is not base64url
     */
    public static byte[] fromBase64Url(String text) {
        return Base64.getUrlDecoder().decode(text);
    }
}
