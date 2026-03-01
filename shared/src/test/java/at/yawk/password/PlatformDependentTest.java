package at.yawk.password;

import java.util.concurrent.ThreadLocalRandom;
import java.util.HexFormat;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * @author yawkat
 */
public class PlatformDependentTest {
    @Test
    public void testPrintHexBinary() {
        for (int i = 0; i < 10; i++) {
            byte[] bytes = new byte[(i + 1) * 10];
            ThreadLocalRandom.current().nextBytes(bytes);

            assertEquals(PlatformDependent.printHexBinary(bytes),
                         HexFormat.of().formatHex(bytes));
        }
    }
}