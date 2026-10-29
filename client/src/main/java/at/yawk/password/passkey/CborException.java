package at.yawk.password.passkey;

/**
 * Invalid or unsupported CBOR, see {@link Cbor#decode}.
 *
 * @author yawkat
 */
public class CborException extends Exception {
    public CborException(String message) {
        super(message);
    }
}
