package at.yawk.password.server;

import io.micronaut.runtime.Micronaut;
import java.io.File;
import java.util.Map;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

/**
 * Command line entry point: {@code -p <port>} (default 8080) and {@code -d <data directory>} (default {@code .}).
 *
 * @author yawkat
 */
public final class DatabaseServer {
    private DatabaseServer() {}

    public static void main(String[] args) {
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

        // the command line was parsed above, so give Micronaut no arguments to interpret
        Micronaut.build(new String[0])
                .mainClass(DatabaseServer.class)
                .banner(false)
                // skip probing for cloud platforms, we never run with environment-specific config
                .deduceEnvironment(false)
                .properties(Map.of(
                        "micronaut.server.port", port.value(set),
                        DatabaseState.DATA_DIR_PROPERTY, directory.value(set).getPath()
                ))
                .start();
    }
}
