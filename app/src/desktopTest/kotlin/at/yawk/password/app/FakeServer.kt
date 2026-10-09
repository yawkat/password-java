package at.yawk.password.app

import at.yawk.password.AuthProtocol
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

/**
 * Minimal in-memory stand-in for the password server that stores the registration and `/db` without checking
 * signatures. The client's tests cover the real server.
 */
class FakeServer : AutoCloseable {
    val db = AtomicReference<ByteArray?>()
    val registration = AtomicReference<ByteArray?>()
    /** The 2FA vault, below /totp */
    val totpDb = AtomicReference<ByteArray?>()
    val totpRegistration = AtomicReference<ByteArray?>()

    /** If set, uploads of the database wait for it, like a stuck connection */
    @Volatile
    var uploadGate: CountDownLatch? = null
    private val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)

    init {
        server.createContext("/") { exchange ->
            exchange.use {
                val fullPath = exchange.requestURI.path
                val totp = fullPath.startsWith(AuthProtocol.TOTP_VAULT_PREFIX + "/")
                val path = if (totp) fullPath.substring(AuthProtocol.TOTP_VAULT_PREFIX.length) else fullPath
                val registration = if (totp) totpRegistration else registration
                val db = if (totp) totpDb else db
                val body = when {
                    path == "/salt" -> registration.get()?.copyOf(AuthProtocol.SALT_RESPONSE_LENGTH)
                    path == "/register" -> {
                        registration.set(exchange.requestBody.readAllBytes())
                        ByteArray(0)
                    }
                    path == "/db" && exchange.requestMethod == "PUT" -> {
                        uploadGate?.await()
                        db.set(exchange.requestBody.readAllBytes())
                        ByteArray(0)
                    }
                    path == "/db" -> db.get()
                    else -> null
                }
                if (body == null) {
                    exchange.sendResponseHeaders(404, -1)
                } else {
                    exchange.sendResponseHeaders(200, if (body.isEmpty()) -1 else body.size.toLong())
                    exchange.responseBody.write(body)
                }
            }
        }
        server.start()
    }

    val url: String get() = "http://127.0.0.1:${server.address.port}"

    override fun close() = server.stop(0)
}
