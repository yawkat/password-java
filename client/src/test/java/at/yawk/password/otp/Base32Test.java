package at.yawk.password.otp;

import java.nio.charset.StandardCharsets;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class Base32Test {
    @DataProvider
    public Object[][] rfc4648() {
        // RFC 4648, section 10, without the padding that encode leaves out
        return new Object[][]{
                {"", ""},
                {"f", "MY"},
                {"fo", "MZXQ"},
                {"foo", "MZXW6"},
                {"foob", "MZXW6YQ"},
                {"fooba", "MZXW6YTB"},
                {"foobar", "MZXW6YTBOI"},
        };
    }

    @Test(dataProvider = "rfc4648")
    public void vectors(String plain, String encoded) {
        byte[] bytes = plain.getBytes(StandardCharsets.US_ASCII);
        Assert.assertEquals(Base32.encode(bytes), encoded);
        Assert.assertEquals(Base32.decode(encoded), bytes);
    }

    @Test
    public void lenientDecoding() {
        byte[] foobar = "foobar".getBytes(StandardCharsets.US_ASCII);
        Assert.assertEquals(Base32.decode("MZXW6YTBOI======"), foobar);
        Assert.assertEquals(Base32.decode("mzxw 6ytb-oi"), foobar);
        Assert.assertEquals(Base32.normalize("mzxw 6ytb-oi=="), "MZXW6YTBOI");
    }

    @Test
    public void rejectsInvalid() {
        Assert.assertThrows(IllegalArgumentException.class, () -> Base32.decode("MZXW1"));
        Assert.assertThrows(IllegalArgumentException.class, () -> Base32.decode("MZXW8"));
        // padding in the middle
        Assert.assertThrows(IllegalArgumentException.class, () -> Base32.decode("MY==MY"));
        // lengths that no byte sequence encodes to
        Assert.assertThrows(IllegalArgumentException.class, () -> Base32.decode("M"));
        Assert.assertThrows(IllegalArgumentException.class, () -> Base32.decode("MZX"));
        Assert.assertThrows(IllegalArgumentException.class, () -> Base32.decode("MZXW6Y"));
    }
}
