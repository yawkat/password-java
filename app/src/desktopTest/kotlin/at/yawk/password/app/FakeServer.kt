package at.yawk.password.app

import at.yawk.password.HashUtil
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicReference

/**
 * Minimal in-memory stand-in for the password server that stores `/db` without checking tokens, like the one in the
 * client's `PasswordStoreTest`.
 */
class FakeServer : AutoCloseable {
    val db = AtomicReference<ByteArray?>()
    private val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)

    init {
        server.createContext("/") { exchange ->
            exchange.use {
                val path = exchange.requestURI.path
                val body = when {
                    path == "/challenge" -> HashUtil.generateRandomBytes(32)
                    path == "/db" && exchange.requestMethod == "PUT" -> {
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
