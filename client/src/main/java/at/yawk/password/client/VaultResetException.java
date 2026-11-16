package at.yawk.password.client;

/**
 * The server has no registration of the vault, so an exported key can't open it from the server, or save to it: the
 * vault was reset. Unlike {@link WrongPasswordException} for an exported key of another install salt, this is only what
 * the server (or whatever answered in its place, e.g. a proxy during an outage) said, not proof that the key is no
 * longer valid.
 *
 * @author yawkat
 */
public class VaultResetException extends WrongPasswordException {
    VaultResetException() {
        super("The server has no registration of this vault: it was reset, or the server has a problem. Unlock it " +
              "with its password to create it again.");
    }
}
