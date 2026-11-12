package at.yawk.password.client;

/**
 * The database decrypted fine, but its content can't be read: a newer version of the app saved it with a higher reader
 * version, or with data that this one doesn't know without raising the writer version (see SPEC.md, "Schema
 * versions"). Unlike a copy that doesn't decrypt, this is no reason to fall back to the local
 * copy: saving that would replace the newer data on the server.
 */
public class UnreadableDatabaseException extends Exception {
    /**
     * The revision of the database, or -1 if not even that could be read.
     */
    final long revision;

    UnreadableDatabaseException(Throwable cause, long revision) {
        super("The database was saved by a newer version of the app, update this one to open it (" +
              cause.getMessage() + ")", cause);
        this.revision = revision;
    }

    UnreadableDatabaseException(String reason, long revision) {
        super("The database was saved by a newer version of the app, update this one to open it (" + reason + ")");
        this.revision = revision;
    }
}
