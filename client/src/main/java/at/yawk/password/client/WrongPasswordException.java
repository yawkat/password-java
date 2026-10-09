package at.yawk.password.client;

/**
 * The database could not be decrypted: the password is wrong, or the data was tampered with. The two can't be told
 * apart.
 *
 * @author yawkat
 */
public class WrongPasswordException extends Exception {
    WrongPasswordException() {
        super("Wrong password, or the database was tampered with");
    }

    WrongPasswordException(String message) {
        super(message);
    }
}
