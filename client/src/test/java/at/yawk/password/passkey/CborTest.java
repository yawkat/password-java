package at.yawk.password.passkey;

import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * @author yawkat
 */
public class CborTest {
    private static byte[] hex(String hex) {
        return HexFormat.of().parseHex(hex);
    }

    /**
     * Examples of RFC 8949, appendix A
     */
    @DataProvider
    public Object[][] vectors() {
        return new Object[][]{
                {0L, "00"},
                {23L, "17"},
                {24L, "1818"},
                {100L, "1864"},
                {1000L, "1903e8"},
                {1000000L, "1a000f4240"},
                {1000000000000L, "1b000000e8d4a51000"},
                {Long.MAX_VALUE, "1b7fffffffffffffff"},
                {Long.MIN_VALUE, "3b7fffffffffffffff"},
                {-1L, "20"},
                {-10L, "29"},
                {-100L, "3863"},
                {-1000L, "3903e7"},
                {false, "f4"},
                {true, "f5"},
                {null, "f6"},
                {"", "60"},
                {"a", "6161"},
                {"IETF", "6449455446"},
                {"ü", "62c3bc"},
                {"𐅑", "64f0908591"},
                {List.of(), "80"},
                {List.of(1L, 2L, 3L), "83010203"},
                {List.of(1L, List.of(2L, 3L), List.of(4L, 5L)), "8301820203820405"},
                {Map.of(), "a0"},
                {Map.of("a", 1L, "b", List.of(2L, 3L)), "a26161016162820203"},
        };
    }

    @Test(dataProvider = "vectors")
    public void testVector(Object value, String hex) throws Exception {
        Assert.assertEquals(HexFormat.of().formatHex(Cbor.encode(value)), hex);
        Assert.assertEquals(Cbor.decode(hex(hex)), value);
    }

    @Test
    public void testBytes() throws Exception {
        Assert.assertEquals(Cbor.encode(new byte[]{1, 2, 3, 4}), hex("4401020304"));
        Assert.assertEquals((byte[]) Cbor.decode(hex("4401020304")), new byte[]{1, 2, 3, 4});
    }

    @Test
    public void testIntegerTypes() {
        Assert.assertEquals(Cbor.encode(5), hex("05"));
        Assert.assertEquals(Cbor.encode((byte) -7), hex("26"));
    }

    @Test
    public void testCanonicalMapOrder() {
        // CTAP2: shorter keys first, then bytewise; integers before text, positive before negative
        Map<Object, Object> map = new LinkedHashMap<>();
        map.put("authData", 3L);
        map.put(-3L, 4L);
        map.put("fmt", 1L);
        map.put(3L, 2L);
        map.put("attStmt", 5L);
        map.put(1L, 6L);
        Assert.assertEquals(HexFormat.of().formatHex(Cbor.encode(map)),
                            "a6" + "0106" + "0302" + "2204" + "63666d7401" + "6761747453746d7405" +
                            "68617574684461746103");
    }

    @Test
    public void testTagIgnored() throws Exception {
        Assert.assertEquals(Cbor.decode(hex("c11a514b67b0")), 1363896240L);
    }

    @DataProvider
    public Object[][] invalid() {
        return new Object[][]{
                {""},
                // trailing byte
                {"0000"},
                // truncated
                {"19"},
                {"62c3"},
                {"8301"},
                // indefinite length
                {"5f42010243030405ff"},
                {"9fff"},
                // float
                {"f93c00"},
                // invalid UTF-8
                {"61ff"},
                // duplicate key
                {"a201020103"},
                // byte string key
                {"a14101 01".replace(" ", "")},
                // length beyond the data
                {"5b7fffffffffffffff"},
                // integer beyond a long
                {"1bffffffffffffffff"},
        };
    }

    @Test(dataProvider = "invalid", expectedExceptions = CborException.class)
    public void testInvalid(String hex) throws Exception {
        Cbor.decode(hex(hex));
    }

    @Test(expectedExceptions = CborException.class)
    public void testDepth() throws Exception {
        Cbor.decode(hex("81".repeat(100) + "00"));
    }
}
