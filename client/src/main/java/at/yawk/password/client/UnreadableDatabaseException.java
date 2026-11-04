package at.yawk.password.client;

/**
 * The database decrypted fine, but its content can't be read: most likely a newer version of the app saved it with
 * fields that this one doesn't know. Unlike a copy that doesn't decrypt, this is no reason to fall back to the local
 * copy: saving that would replace the newer data on the server.
 */
public class UnreadableDatabaseException extends Exception {
    UnreadableDatabaseException(Throwable cause) {
        super("The database was saved by a newer version of the app, update this one to open it (" +
              cause.getMessage() + ")", cause);
    }
}
