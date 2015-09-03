package at.yawk.password;

import java.util.concurrent.ThreadLocalRandom;
import javax.xml.bind.DatatypeConverter;
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
                         DatatypeConverter.printHexBinary(bytes).toLowerCase());
        }
    }
}