package at.yawk.password.app

import com.fasterxml.jackson.databind.ObjectMapper
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URISyntaxException

/**
 * Digital Asset Links (`https://<domain>/.well-known/assetlinks.json`): a website names the Android apps that may use
 * its passkeys. Android's credential manager leaves this check to the passkey provider for apps (browsers name the
 * website themselves).
 */
object AssetLinks {
    private val mapper = ObjectMapper()
    private val relations = setOf(
        "delegate_permission/common.get_login_creds",
        "delegate_permission/common.handle_all_urls",
    )
    private const val MAX_SIZE = 1024 * 1024
    private const val TIMEOUT_MS = 10_000

    /**
     * Whether the statements in [json] let the app [packageName], signed by a certificate with one of the SHA-256
     * [fingerprints] (upper-case hex, colon-separated, as in the file), sign in to the website.
     */
    fun allows(json: String, packageName: String, fingerprints: Collection<String>): Boolean {
        val statements = try {
            mapper.readTree(json)
        } catch (e: IOException) {
            return false
        }
        if (statements == null || !statements.isArray) {
            return false
        }
        val wanted = fingerprints.map { it.uppercase() }.toSet()
        return statements.any { statement ->
            val target = statement.path("target")
            statement.path("relation").any { it.asText() in relations } &&
                target.path("namespace").asText() == "android_app" &&
                target.path("package_name").asText() == packageName &&
                target.path("sha256_cert_fingerprints").any { it.asText().uppercase() in wanted }
        }
    }

    /**
     * Load the statements of [domain]. Redirects are not followed, as Digital Asset Links requires.
     *
     * @throws IOException if they can't be loaded
     * @throws IllegalArgumentException if [domain] is not a domain
     */
    fun fetch(domain: String): String {
        require(domain.isNotEmpty() && domain.none { it == '/' || it == '@' || it == ':' || it == '?' || it == '#' }) {
            "Invalid domain $domain"
        }
        val url = try {
            URI("https", domain, "/.well-known/assetlinks.json", null).toURL()
        } catch (e: URISyntaxException) {
            throw IllegalArgumentException("Invalid domain $domain", e)
        }
        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                throw IOException("${connection.url}: HTTP ${connection.responseCode}")
            }
            val bytes = connection.inputStream.use { it.readNBytesCompat(MAX_SIZE + 1) }
            if (bytes.size > MAX_SIZE) {
                throw IOException("${connection.url} is too large")
            }
            return bytes.decodeToString()
        } finally {
            connection.disconnect()
        }
    }

    /** InputStream.readNBytes(int) is Java 11, newer than Android 10 has */
    private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (out.size() < limit) {
            val read = read(buffer, 0, minOf(buffer.size, limit - out.size()))
            if (read < 0) break
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }
}
