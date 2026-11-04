package at.yawk.password.app

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AssetLinksTest {
    private val fingerprint = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"

    private fun statement(
        relation: String = "delegate_permission/common.get_login_creds",
        namespace: String = "android_app",
        packageName: String = "com.example.app",
        fingerprint: String = this.fingerprint,
    ) = """
        {
          "relation": ["delegate_permission/common.other", "$relation"],
          "target": {
            "namespace": "$namespace",
            "package_name": "$packageName",
            "sha256_cert_fingerprints": ["AA:BB", "$fingerprint"]
          }
        }
    """.trimIndent()

    @Test
    fun allows() {
        assertTrue(AssetLinks.allows("[${statement()}]", "com.example.app", listOf(fingerprint)))
        assertTrue(AssetLinks.allows("[${statement()}]", "com.example.app", listOf("00", fingerprint.lowercase())))
        assertTrue(AssetLinks.allows(
            "[${statement(packageName = "other")}, ${statement(relation = "delegate_permission/common.handle_all_urls")}]",
            "com.example.app",
            listOf(fingerprint),
        ))
    }

    @Test
    fun refuses() {
        assertFalse(AssetLinks.allows("[${statement()}]", "com.example.other", listOf(fingerprint)))
        assertFalse(AssetLinks.allows("[${statement()}]", "com.example.app", listOf("00")))
        assertFalse(AssetLinks.allows("[${statement()}]", "com.example.app", emptyList()))
        assertFalse(AssetLinks.allows(
            "[${statement(relation = "delegate_permission/common.other")}]", "com.example.app", listOf(fingerprint),
        ))
        assertFalse(AssetLinks.allows("[${statement(namespace = "web")}]", "com.example.app", listOf(fingerprint)))
        assertFalse(AssetLinks.allows(statement(), "com.example.app", listOf(fingerprint)))
        assertFalse(AssetLinks.allows("not json", "com.example.app", listOf(fingerprint)))
        assertFalse(AssetLinks.allows("", "com.example.app", listOf(fingerprint)))
    }

    @Test
    fun invalidDomain() {
        val domains = listOf("", "example.com/x", "user@example.com", "example.com:443", "example.com?x")
        // not even a URI
        for (domain in domains + listOf("ex ample", "a\\b")) {
            assertFailsWith<IllegalArgumentException> { AssetLinks.fetch(domain) }
        }
    }
}
