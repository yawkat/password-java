package at.yawk.password.app.fido

import at.yawk.password.app.PasskeyOutcome
import at.yawk.password.app.PasskeyRequest
import at.yawk.password.model.Passkey
import at.yawk.password.passkey.Cbor
import at.yawk.password.passkey.PasskeyAuthenticator
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking

class Ctap2Test {
    private val clientDataHash = ByteArray(32) { it.toByte() }

    /** The passkeys "in the database" */
    private val passkeys = mutableListOf<Passkey>()
    private var unlocked = true
    private val requests = mutableListOf<PasskeyRequest>()

    /** Answers a request */
    private lateinit var answer: suspend (PasskeyRequest) -> PasskeyOutcome

    /** Creates, or chooses the first candidate */
    private val approve: suspend (PasskeyRequest) -> PasskeyOutcome = { request ->
        when (request) {
            is PasskeyRequest.Create -> if (request.excluded(passkeys) != null) {
                PasskeyOutcome.Excluded
            } else {
                passkeys += request.passkey
                PasskeyOutcome.Created
            }
            is PasskeyRequest.Get -> request.candidates(passkeys).firstOrNull()?.let { PasskeyOutcome.Chosen(it) }
                ?: PasskeyOutcome.NoCredentials
        }
    }

    // TestNG runs all tests on the same instance
    @BeforeTest
    fun setUp() {
        passkeys.clear()
        requests.clear()
        unlocked = true
        answer = approve
    }

    private val ctap2 = Ctap2(
        handler = {
            requests += it
            answer(it)
        },
        unlockedPasskeys = { if (unlocked) passkeys.toList() else null },
        clock = { 1234 },
        userTimeoutMs = 500,
    )

    private fun call(command: Byte, parameters: Map<Long, Any>? = null): Pair<Byte, Map<*, *>?> = runBlocking {
        val request = byteArrayOf(command) + (parameters?.let { Cbor.encode(it) } ?: ByteArray(0))
        val response = ctap2.process(request)
        response[0] to if (response.size > 1) Cbor.decode(response.copyOfRange(1, response.size)) as Map<*, *> else null
    }

    private fun makeCredentialParameters(
        userId: ByteArray = byteArrayOf(1, 2, 3),
        algorithms: List<Long> = listOf(-8, -7),
        exclude: List<ByteArray> = emptyList(),
    ) = buildMap<Long, Any> {
        put(1L, clientDataHash)
        put(2L, mapOf("id" to "example.com", "name" to "Example"))
        put(3L, mapOf("id" to userId, "name" to "alice@example.com", "displayName" to "Alice"))
        put(4L, algorithms.map { mapOf("alg" to it, "type" to "public-key") })
        if (exclude.isNotEmpty()) put(5L, exclude.map { mapOf("id" to it, "type" to "public-key") })
        put(7L, mapOf("rk" to true))
    }

    private fun getAssertionParameters(allow: List<ByteArray> = emptyList(), up: Boolean? = null) = buildMap<Long, Any> {
        put(1L, "example.com")
        put(2L, clientDataHash)
        if (allow.isNotEmpty()) put(3L, allow.map { mapOf("id" to it, "type" to "public-key") })
        if (up != null) put(5L, mapOf("up" to up))
    }

    /**
     * The public key in the attested credential data of [authData], checked by the JDK.
     */
    private fun publicKey(authData: ByteArray): Pair<ByteArray, PublicKey> {
        val buffer = ByteBuffer.wrap(authData, 37 + 16, authData.size - 37 - 16)
        val credentialId = ByteArray(buffer.short.toInt())
        buffer.get(credentialId)
        val cose = ByteArray(buffer.remaining())
        buffer.get(cose)
        val key = Cbor.decode(cose) as Map<*, *>
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val point = ECPoint(BigInteger(1, key[-2L] as ByteArray), BigInteger(1, key[-3L] as ByteArray))
        val spec = ECPublicKeySpec(point, parameters.getParameterSpec(ECParameterSpec::class.java))
        return credentialId to KeyFactory.getInstance("EC").generatePublic(spec)
    }

    private fun verify(publicKey: PublicKey, authData: ByteArray, signature: ByteArray): Boolean {
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(authData)
        verifier.update(clientDataHash)
        return verifier.verify(signature)
    }

    @Test
    fun getInfo() {
        val (status, info) = call(CMD_GET_INFO)
        assertEquals(CTAP2_OK, status)
        assertEquals(listOf("FIDO_2_0"), info!![1L])
        assertContentEquals(ByteArray(16), info[3L] as ByteArray)
        assertEquals(mapOf("rk" to true, "up" to true, "uv" to true, "plat" to false), info[4L])
    }

    @Test
    fun registerAndSignIn() {
        val (status, response) = call(CMD_MAKE_CREDENTIAL, makeCredentialParameters())
        assertEquals(CTAP2_OK, status)
        assertEquals("none", response!![1L])
        assertEquals(emptyMap<Any, Any>(), response[3L])
        val authData = response[2L] as ByteArray
        assertContentEquals(PasskeyAuthenticator.sha256("example.com".toByteArray()), authData.copyOf(32))
        // UP, UV, BE, BS, AT
        assertEquals(0x5d, authData[32].toInt())

        val passkey = passkeys.single()
        assertEquals("example.com", passkey.rpId)
        assertEquals("alice@example.com", passkey.userName)
        assertEquals("Alice", passkey.userDisplayName)
        assertEquals(1234, passkey.created)
        assertContentEquals(byteArrayOf(1, 2, 3), PasskeyAuthenticator.userHandle(passkey))
        val (credentialId, publicKey) = publicKey(authData)
        assertContentEquals(PasskeyAuthenticator.credentialId(passkey), credentialId)

        // discoverable
        val (getStatus, assertion) = call(CMD_GET_ASSERTION, getAssertionParameters())
        assertEquals(CTAP2_OK, getStatus)
        assertContentEquals(credentialId, (assertion!![1L] as Map<*, *>)["id"] as ByteArray)
        val assertionAuthData = assertion[2L] as ByteArray
        assertEquals(37, assertionAuthData.size)
        assertEquals(0x1d, assertionAuthData[32].toInt())
        assertTrue(verify(publicKey, assertionAuthData, assertion[3L] as ByteArray))
        val user = assertion[4L] as Map<*, *>
        assertContentEquals(byteArrayOf(1, 2, 3), user["id"] as ByteArray)
        assertEquals("alice@example.com", user["name"])
        assertEquals("Alice", user["displayName"])
        assertNull(assertion[5L])

        // with an allow list, the user's details are left out
        val (_, allowed) = call(CMD_GET_ASSERTION, getAssertionParameters(allow = listOf(ByteArray(3), credentialId)))
        assertEquals(setOf("id"), (allowed!![4L] as Map<*, *>).keys)
        assertTrue(verify(publicKey, allowed[2L] as ByteArray, allowed[3L] as ByteArray))
        val get = requests.last() as PasskeyRequest.Get
        assertEquals("example.com", get.rpId)
        assertEquals(2, get.allowCredentials.size)
    }

    @Test
    fun excluded() {
        call(CMD_MAKE_CREDENTIAL, makeCredentialParameters())
        val existing = PasskeyAuthenticator.credentialId(passkeys.single())
        val (status, _) = call(CMD_MAKE_CREDENTIAL, makeCredentialParameters(exclude = listOf(existing)))
        assertEquals(CTAP2_ERR_CREDENTIAL_EXCLUDED, status)
        assertEquals(1, passkeys.size)
        // the user was asked all the same
        assertEquals(2, requests.size)
    }

    @Test
    fun unsupportedAlgorithm() {
        val (status, _) = call(CMD_MAKE_CREDENTIAL, makeCredentialParameters(algorithms = listOf(-257)))
        assertEquals(CTAP2_ERR_UNSUPPORTED_ALGORITHM, status)
        assertTrue(requests.isEmpty())
    }

    @Test
    fun invalidParameters() {
        assertEquals(CTAP1_ERR_INVALID_LENGTH, call(CMD_MAKE_CREDENTIAL, makeCredentialParameters(userId = ByteArray(0))).first)
        assertEquals(CTAP1_ERR_INVALID_LENGTH, call(CMD_MAKE_CREDENTIAL, makeCredentialParameters(userId = ByteArray(65))).first)
        assertEquals(CTAP2_ERR_MISSING_PARAMETER, call(CMD_MAKE_CREDENTIAL, mapOf(1L to clientDataHash)).first)
        assertEquals(
            CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            call(CMD_MAKE_CREDENTIAL, makeCredentialParameters() + (2L to "example.com")).first,
        )
        assertEquals(
            CTAP2_ERR_INVALID_OPTION,
            call(CMD_MAKE_CREDENTIAL, makeCredentialParameters() + (7L to mapOf("up" to false))).first,
        )
        assertEquals(CTAP2_ERR_PIN_NOT_SET, call(CMD_MAKE_CREDENTIAL, makeCredentialParameters() + (8L to ByteArray(0))).first)
        assertEquals(CTAP2_ERR_INVALID_CBOR, runBlocking { ctap2.process(byteArrayOf(CMD_GET_ASSERTION, 0xff.toByte())) }[0])
        assertEquals(
            CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            runBlocking { ctap2.process(byteArrayOf(CMD_GET_ASSERTION) + Cbor.encode(listOf(1L))) }[0],
        )
        assertEquals(CTAP1_ERR_INVALID_LENGTH, runBlocking { ctap2.process(ByteArray(0)) }[0])
        assertEquals(CTAP1_ERR_INVALID_COMMAND, call(0x40).first)
        assertEquals(CTAP2_ERR_NOT_ALLOWED, call(CMD_RESET).first)
        assertEquals(CTAP2_ERR_NOT_ALLOWED, call(CMD_GET_NEXT_ASSERTION).first)
        assertTrue(requests.isEmpty())
    }

    @Test
    fun noCredentials() {
        assertEquals(CTAP2_ERR_NO_CREDENTIALS, call(CMD_GET_ASSERTION, getAssertionParameters()).first)
        assertIs<PasskeyRequest.Get>(requests.single())
    }

    @Test
    fun denied() {
        answer = { PasskeyOutcome.Denied }
        assertEquals(CTAP2_ERR_OPERATION_DENIED, call(CMD_MAKE_CREDENTIAL, makeCredentialParameters()).first)
        assertEquals(CTAP2_ERR_OPERATION_DENIED, call(CMD_GET_ASSERTION, getAssertionParameters()).first)
        answer = { PasskeyOutcome.Failed }
        assertEquals(CTAP2_ERR_OPERATION_DENIED, call(CMD_MAKE_CREDENTIAL, makeCredentialParameters()).first)
    }

    @Test
    fun timeout() {
        answer = { awaitCancellation() }
        assertEquals(CTAP2_ERR_USER_ACTION_TIMEOUT, call(CMD_GET_ASSERTION, getAssertionParameters()).first)
    }

    @Test
    fun silentAssertion() {
        call(CMD_MAKE_CREDENTIAL, makeCredentialParameters())
        val passkey = passkeys.single()
        requests.clear()
        val credentialId = PasskeyAuthenticator.credentialId(passkey)
        val (status, assertion) = call(CMD_GET_ASSERTION, getAssertionParameters(listOf(credentialId), up = false))
        assertEquals(CTAP2_OK, status)
        // BE, BS: neither present nor verified
        assertEquals(0x18, (assertion!![2L] as ByteArray)[32].toInt())
        // nobody was asked
        assertTrue(requests.isEmpty())

        assertEquals(
            CTAP2_ERR_NO_CREDENTIALS,
            call(CMD_GET_ASSERTION, getAssertionParameters(listOf(ByteArray(4)), up = false)).first,
        )
        // while locked, nothing is known
        unlocked = false
        assertEquals(
            CTAP2_ERR_NO_CREDENTIALS,
            call(CMD_GET_ASSERTION, getAssertionParameters(listOf(credentialId), up = false)).first,
        )
        assertTrue(requests.isEmpty())
    }

    /**
     * The whole stack, but the device: CTAPHID framing of a registration and sign-in.
     */
    @Test
    fun overHid() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val host = FakeHidHost()
            host.hid = CtapHid({ host.reports.add(it) }, scope, ctap2::process)
            val channel = host.init()
            val created = host.cbor(channel, byteArrayOf(CMD_MAKE_CREDENTIAL) + Cbor.encode(makeCredentialParameters()))
            assertEquals(CTAP2_OK, created[0])
            val authData = (Cbor.decode(created.copyOfRange(1, created.size)) as Map<*, *>)[2L] as ByteArray
            val (_, publicKey) = publicKey(authData)
            val assertion = host.cbor(channel, byteArrayOf(CMD_GET_ASSERTION) + Cbor.encode(getAssertionParameters()))
            assertEquals(CTAP2_OK, assertion[0])
            val response = Cbor.decode(assertion.copyOfRange(1, assertion.size)) as Map<*, *>
            assertTrue(verify(publicKey, response[2L] as ByteArray, response[3L] as ByteArray))
        } finally {
            scope.cancel()
        }
    }
}
