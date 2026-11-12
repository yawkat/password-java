package at.yawk.password.client;

/**
 * A save of a database that was opened read-only: a client of a newer writer version saved it, so it may hold data
 * that this one skipped, which a save would drop. See {@link VaultStore#isReadOnly()}.
 */
public class ReadOnlyDatabaseException extends Exception {
    ReadOnlyDatabaseException() {
        super("The database was saved by a newer version of the app, so this one can only show it. Update the app " +
              "to edit it.");
    }
}
