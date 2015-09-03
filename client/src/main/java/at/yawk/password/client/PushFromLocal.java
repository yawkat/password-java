package at.yawk.password.client;

import at.yawk.password.MultiFileLocalStorageProvider;
import at.yawk.password.model.PasswordBlob;
import java.io.File;

/**
 * @author yawkat
 */
public class PushFromLocal {
    public static void main(String[] args) throws Exception {
        MultiFileLocalStorageProvider storageProvider = new MultiFileLocalStorageProvider(new File(
                "/home/yawkat/.local/share/password"));

        System.out.println("http://loading local");
        PasswordBlob blob = new PasswordClient("pw.yawk.at:1", storageProvider, args[0].getBytes())
                .load().getValue();

        assert blob != null;

        int length = blob.toString().length();
        System.out.println("blob string length: " + length);
        if (length < 10000) { return; } // something is wrong

        System.out.println("saving remote");
        new PasswordClient("http://pw.yawk.at", storageProvider, args[0].getBytes()).save(blob);
    }
}
