package at.yawk.password.server;

import at.yawk.password.LocalStorageProvider;
import at.yawk.password.MultiFileLocalStorageProvider;
import java.io.File;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

/**
 * @author yawkat
 */
public class Main {
    public static void main(String[] args) throws Exception {
        OptionParser parser = new OptionParser();
        OptionSpec<File> directory = parser.accepts("d")
                .withRequiredArg()
                .ofType(File.class)
                .defaultsTo(new File("."));
        OptionSpec<Integer> port = parser.accepts("p")
                .withRequiredArg()
                .ofType(Integer.class)
                .defaultsTo(8080);
        OptionSet set = parser.parse(args);

        LocalStorageProvider storageProvider = new MultiFileLocalStorageProvider(directory.value(set));

        try (PasswordServer server = PasswordServer.Factory.create()) {
            server.setStorageProvider(storageProvider);
            server.bind(port.value(set));
            Object o = new Object();
            //noinspection SynchronizationOnLocalVariableOrMethodParameter
            synchronized (o) {
                o.wait();
            }
        }
    }
}
