package at.yawk.password.client;

/**
 * The database decrypted fine, but its content can't be read: a newer version of the app saved it with a higher reader
 * version, or with data that this one doesn't know without raising the writer version (see SPEC.md, "Schema
 * versions"). Unlike a copy that doesn't decrypt, this is no reason to fall back to the local
 * copy: saving that would replace the newer data on the server.
 */
public class UnreadableDatabaseException extends Exception {
    UnreadableDatabaseException(Throwable cause) {
        super("The database was saved by a newer version of the app, update this one to open it (" +
              cause.getMessage() + ")", cause);
    }

    UnreadableDatabaseException(String reason) {
        super("The database was saved by a newer version of the app, update this one to open it (" + reason + ")");
    }
}
