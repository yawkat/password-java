package at.yawk.password.app.fido

import java.nio.ByteBuffer
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

class CtapHidTest {
    private lateinit var scope: CoroutineScope
    private lateinit var host: FakeHidHost

    /** What the fake CTAP2 layer returns; completed by the test when it should answer */
    @Volatile
    private var answer = CompletableDeferred<ByteArray>()
    private val requests = mutableListOf<ByteArray>()
    private var winks = 0

    @BeforeTest
    fun setUp() {
        answer = CompletableDeferred()
        synchronized(requests) { requests.clear() }
        winks = 0
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        host = FakeHidHost()
        host.hid = CtapHid(
            send = { host.reports.add(it) },
            scope = scope,
            process = {
                synchronized(requests) { requests += it }
                answer.await()
            },
            wink = { winks++ },
            keepaliveIntervalMs = 50,
            messageTimeoutMs = 200,
        )
    }

    @AfterTest
    fun tearDown() {
        scope.cancel()
    }

    @Test
    fun initAllocatesChannels() {
        val a = host.init()
        val b = host.init()
        assertNotEquals(a, b)
        assertNotEquals(0, a)
        assertNotEquals(CtapHid.BROADCAST, a)
    }

    @Test
    fun initResponse() {
        host.send(CtapHid.BROADCAST, CtapHid.CTAPHID_INIT, ByteArray(8))
        val data = host.receive().data
        // protocol version 2, then the capabilities: WINK, CBOR, NMSG
        assertEquals(2, data[12].toInt())
        assertEquals(0x0d, data[16].toInt())
    }

    @Test
    fun ping() {
        val channel = host.init()
        // several continuation packets
        val data = ByteArray(300) { it.toByte() }
        host.send(channel, CtapHid.CTAPHID_PING, data)
        val response = host.receive()
        assertEquals(CtapHid.CTAPHID_PING, response.command)
        assertContentEquals(data, response.data)
    }

    @Test
    fun wink() {
        val channel = host.init()
        host.send(channel, CtapHid.CTAPHID_WINK, ByteArray(0))
        assertEquals(CtapHid.CTAPHID_WINK, host.receive().command)
        assertEquals(1, winks)
    }

    @Test
    fun cborWithKeepalive() {
        val channel = host.init()
        val request = ByteArray(100) { (it + 1).toByte() }
        host.send(channel, CtapHid.CTAPHID_CBOR, request)
        // waiting for the user
        val keepalive = host.receiveAny()
        assertEquals(CtapHid.CTAPHID_KEEPALIVE, keepalive.command)
        assertContentEquals(byteArrayOf(CtapHid.KEEPALIVE_STATUS_UPNEEDED), keepalive.data)
        answer.complete(byteArrayOf(0, 1, 2))
        val response = host.receive()
        assertEquals(CtapHid.CTAPHID_CBOR, response.command)
        assertContentEquals(byteArrayOf(0, 1, 2), response.data)
        assertContentEquals(request, synchronized(requests) { requests.single() })
    }

    @Test
    fun cancel() {
        val channel = host.init()
        host.send(channel, CtapHid.CTAPHID_CBOR, byteArrayOf(2))
        host.receiveAny()
        host.send(channel, CtapHid.CTAPHID_CANCEL, ByteArray(0))
        val response = host.receive()
        assertEquals(CtapHid.CTAPHID_CBOR, response.command)
        assertContentEquals(byteArrayOf(CTAP2_ERR_KEEPALIVE_CANCEL), response.data)
    }

    @Test
    fun busy() {
        val a = host.init()
        val b = host.init()
        host.send(a, CtapHid.CTAPHID_CBOR, byteArrayOf(2))
        host.send(b, CtapHid.CTAPHID_PING, byteArrayOf(1))
        val busy = host.receive()
        assertEquals(b, busy.channel)
        assertEquals(CtapHid.CTAPHID_ERROR, busy.command)
        assertContentEquals(byteArrayOf(CtapHid.ERR_CHANNEL_BUSY), busy.data)
        // a cancel from another channel is ignored
        host.send(b, CtapHid.CTAPHID_CANCEL, ByteArray(0))
        answer.complete(byteArrayOf(0))
        val response = host.receive()
        assertEquals(a, response.channel)
        assertContentEquals(byteArrayOf(0), response.data)
        // free again
        answer = CompletableDeferred(byteArrayOf(0, 5))
        assertContentEquals(byteArrayOf(0, 5), host.cbor(b, byteArrayOf(4)))
    }

    @Test
    fun resyncAbandonsRequest() {
        val channel = host.init()
        host.send(channel, CtapHid.CTAPHID_CBOR, byteArrayOf(2))
        host.receiveAny()
        val nonce = ByteArray(8) { 9 }
        host.send(channel, CtapHid.CTAPHID_INIT, nonce)
        val response = host.receive()
        assertEquals(CtapHid.CTAPHID_INIT, response.command)
        assertEquals(channel, response.channel)
        assertEquals(channel, ByteBuffer.wrap(response.data, 8, 4).int)
        // the abandoned request sends nothing more, and the key is free
        Thread.sleep(200)
        assertTrue(host.reports.none { ByteBuffer.wrap(it, 4, 1).get().toInt() and 0xff != CtapHid.CTAPHID_KEEPALIVE })
        host.reports.clear()
        host.send(channel, CtapHid.CTAPHID_PING, byteArrayOf(1))
        assertEquals(CtapHid.CTAPHID_PING, host.receive().command)
    }

    @Test
    fun unknownChannel() {
        host.send(0x12345678, CtapHid.CTAPHID_PING, byteArrayOf(1))
        val response = host.receive()
        assertEquals(CtapHid.CTAPHID_ERROR, response.command)
        assertContentEquals(byteArrayOf(CtapHid.ERR_INVALID_CHANNEL), response.data)
    }

    @Test
    fun unknownCommand() {
        val channel = host.init()
        host.send(channel, CtapHid.CTAPHID_MSG, byteArrayOf(0, 1, 0, 0))
        val response = host.receive()
        assertEquals(CtapHid.CTAPHID_ERROR, response.command)
        assertContentEquals(byteArrayOf(CtapHid.ERR_INVALID_CMD), response.data)
    }

    @Test
    fun wrongSequence() {
        val channel = host.init()
        val reports = FakeHidHost.frame(channel, CtapHid.CTAPHID_PING, ByteArray(200))
        host.sendReport(reports[0])
        host.sendReport(reports[2])
        val response = host.receive()
        assertEquals(CtapHid.CTAPHID_ERROR, response.command)
        assertContentEquals(byteArrayOf(CtapHid.ERR_INVALID_SEQ), response.data)
    }

    @Test
    fun messageTimeout() {
        val channel = host.init()
        host.sendReport(FakeHidHost.frame(channel, CtapHid.CTAPHID_PING, ByteArray(200))[0])
        val response = host.receive()
        assertEquals(CtapHid.CTAPHID_ERROR, response.command)
        assertContentEquals(byteArrayOf(CtapHid.ERR_MSG_TIMEOUT), response.data)
    }

    @Test
    fun tooLong() {
        val channel = host.init()
        val report = FakeHidHost.frame(channel, CtapHid.CTAPHID_PING, ByteArray(0))[0]
        ByteBuffer.wrap(report).putShort(5, (CtapHid.MAX_MESSAGE_SIZE + 1).toShort())
        host.sendReport(report)
        assertContentEquals(byteArrayOf(CtapHid.ERR_INVALID_LEN), host.receive().data)
    }

    @Test
    fun ignoresOtherSizes() {
        host.hid.onReport(ByteArray(65))
        assertNull(host.reports.poll(100, TimeUnit.MILLISECONDS))
    }
}
