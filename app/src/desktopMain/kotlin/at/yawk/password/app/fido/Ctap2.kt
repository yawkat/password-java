package at.yawk.password.app.fido

import at.yawk.password.app.PasskeyOutcome
import at.yawk.password.app.PasskeyRequest
import at.yawk.password.model.Passkey
import at.yawk.password.passkey.Cbor
import at.yawk.password.passkey.CborException
import at.yawk.password.passkey.PasskeyAuthenticator
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(Ctap2::class.java)

/**
 * The authenticator API of CTAP 2.0 (FIDO Client to Authenticator Protocol), over the passkeys of the password
 * database: what a browser sends to a security key in the CBOR messages of [CtapHid].
 *
 * Every request that creates or uses a passkey goes to [handler], which asks the user (and waits for the database to be
 * unlocked). The user's approval in the unlocked app counts as user verification, so the key reports built-in user
 * verification and needs no PIN. Only the "silent" sign-in requests that a browser makes to find out whether the key
 * has a credential (without user presence) are answered without asking, from [unlockedPasskeys], and only while the
 * database is unlocked.
 *
 * @param unlockedPasskeys The passkeys of the database, or `null` while it is locked
 * @param clock Milliseconds since the epoch, for the creation time of passkeys
 */
class Ctap2(
    private val handler: suspend (PasskeyRequest) -> PasskeyOutcome,
    private val unlockedPasskeys: () -> List<Passkey>?,
    private val clock: () -> Long = System::currentTimeMillis,
    private val userTimeoutMs: Long = USER_TIMEOUT_MS,
) {
    /**
     * Process one CTAP2 request (command byte and CBOR parameters).
     *
     * @return The response: status byte and CBOR data
     */
    suspend fun process(request: ByteArray): ByteArray {
        if (request.isEmpty()) {
            return byteArrayOf(CTAP1_ERR_INVALID_LENGTH)
        }
        return try {
            val parameters = if (request.size > 1) {
                Cbor.decode(request.copyOfRange(1, request.size)) as? Map<*, *>
                    ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
            } else {
                emptyMap<Any, Any>()
            }
            val response = when (request[0]) {
                CMD_GET_INFO -> getInfo()
                CMD_MAKE_CREDENTIAL -> makeCredential(parameters)
                CMD_GET_ASSERTION -> getAssertion(parameters)
                // we never return more than one credential, and can't be reset
                CMD_GET_NEXT_ASSERTION, CMD_RESET -> throw CtapError(CTAP2_ERR_NOT_ALLOWED)
                else -> throw CtapError(CTAP1_ERR_INVALID_COMMAND)
            }
            byteArrayOf(CTAP2_OK) + Cbor.encode(response)
        } catch (e: CborException) {
            byteArrayOf(CTAP2_ERR_INVALID_CBOR)
        } catch (e: CtapError) {
            byteArrayOf(e.status)
        }
    }

    private fun getInfo(): Map<Long, Any> = mapOf(
        1L to listOf("FIDO_2_0"),
        3L to PasskeyAuthenticator.AAGUID,
        // resident keys, user presence and built-in user verification; no PIN
        4L to mapOf("rk" to true, "up" to true, "uv" to true, "plat" to false),
        5L to CtapHid.MAX_MESSAGE_SIZE.toLong(),
        7L to MAX_CREDENTIAL_COUNT_IN_LIST,
        8L to MAX_CREDENTIAL_ID_LENGTH,
        9L to listOf("usb"),
        10L to listOf(mapOf("type" to "public-key", "alg" to PasskeyAuthenticator.COSE_ES256)),
    )

    private suspend fun makeCredential(parameters: Map<*, *>): Map<Long, Any> {
        val clientDataHash = parameters.bytes(1L)
        val rp = parameters.map(2L)
        val rpId = rp.string("id")
        val user = parameters.map(3L)
        val userId = user.bytes("id")
        val es256 = parameters.list(4L).any {
            val credentialParameters = it as? Map<*, *> ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
            credentialParameters["type"] == "public-key" &&
                credentialParameters["alg"] == PasskeyAuthenticator.COSE_ES256
        }
        val excludeList = credentialIds(parameters.optionalList(5L))
        val options = parameters.optionalMap(7L)
        if (options?.get("up") == false) {
            throw CtapError(CTAP2_ERR_INVALID_OPTION)
        }
        checkNoPin(parameters[8L])
        if (clientDataHash.size != 32 || rpId.isEmpty()) {
            throw CtapError(CTAP1_ERR_INVALID_PARAMETER)
        }
        if (userId.isEmpty() || userId.size > 64) {
            throw CtapError(CTAP1_ERR_INVALID_LENGTH)
        }
        if (!es256) {
            throw CtapError(CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        }
        val passkey = PasskeyAuthenticator.create(
            rpId,
            userId,
            user.optionalString("name").orEmpty(),
            user.optionalString("displayName").orEmpty(),
            clock(),
        )
        return when (ask(PasskeyRequest.Create(passkey, excludeList))) {
            PasskeyOutcome.Created -> mapOf(
                1L to "none",
                2L to PasskeyAuthenticator.registrationAuthData(passkey, true),
                3L to emptyMap<String, Any>(),
            )
            PasskeyOutcome.Excluded -> throw CtapError(CTAP2_ERR_CREDENTIAL_EXCLUDED)
            else -> throw CtapError(CTAP2_ERR_OPERATION_DENIED)
        }
    }

    private suspend fun getAssertion(parameters: Map<*, *>): Map<Long, Any> {
        val rpId = parameters.string(1L)
        val clientDataHash = parameters.bytes(2L)
        val allowList = credentialIds(parameters.optionalList(3L))
        val options = parameters.optionalMap(5L)
        checkNoPin(parameters[6L])
        if (clientDataHash.size != 32 || rpId.isEmpty()) {
            throw CtapError(CTAP1_ERR_INVALID_PARAMETER)
        }
        if (options?.get("rk") != null) {
            throw CtapError(CTAP2_ERR_UNSUPPORTED_OPTION)
        }
        val passkey: Passkey
        val userPresent: Boolean
        if (options?.get("up") == false) {
            // a silent check whether we have one of the listed credentials. Without a list, it would tell any local
            // process which accounts we have.
            if (allowList.isEmpty()) throw CtapError(CTAP2_ERR_NO_CREDENTIALS)
            val passkeys = unlockedPasskeys() ?: throw CtapError(CTAP2_ERR_NO_CREDENTIALS)
            passkey = PasskeyAuthenticator.find(passkeys, rpId, allowList).firstOrNull()
                ?: throw CtapError(CTAP2_ERR_NO_CREDENTIALS)
            userPresent = false
        } else {
            passkey = when (val outcome = ask(PasskeyRequest.Get(rpId, allowList))) {
                is PasskeyOutcome.Chosen -> outcome.passkey
                PasskeyOutcome.NoCredentials -> throw CtapError(CTAP2_ERR_NO_CREDENTIALS)
                else -> throw CtapError(CTAP2_ERR_OPERATION_DENIED)
            }
            userPresent = true
        }
        val authData = PasskeyAuthenticator.assertionAuthData(rpId, userPresent, userPresent)
        return buildMap {
            put(1L, mapOf("id" to PasskeyAuthenticator.credentialId(passkey), "type" to "public-key"))
            put(2L, authData)
            put(3L, PasskeyAuthenticator.sign(passkey, authData, clientDataHash))
            // a silent answer reveals no more than the listed credential that was asked about
            if (userPresent) {
                put(
                    4L,
                    buildMap<String, Any> {
                        put("id", PasskeyAuthenticator.userHandle(passkey))
                        // the account details are only for choosing among discoverable credentials
                        if (allowList.isEmpty()) {
                            if (passkey.userName.isNotEmpty()) put("name", passkey.userName)
                            if (passkey.userDisplayName.isNotEmpty()) put("displayName", passkey.userDisplayName)
                        }
                    },
                )
            }
        }
    }

    private suspend fun ask(request: PasskeyRequest): PasskeyOutcome = try {
        withTimeout(userTimeoutMs) { handler(request) }
    } catch (e: TimeoutCancellationException) {
        log.info("No answer to the passkey request of {} in time", request.rpId)
        throw CtapError(CTAP2_ERR_USER_ACTION_TIMEOUT)
    }

    /**
     * We have no PIN, so a platform should send no PIN parameters. An empty one (CTAP 2.0's way of asking the user to
     * touch the key) is answered as if no PIN was set.
     */
    private fun checkNoPin(pinUvAuthParam: Any?) {
        when (pinUvAuthParam) {
            null -> {}
            is ByteArray ->
                throw CtapError(if (pinUvAuthParam.isEmpty()) CTAP2_ERR_PIN_NOT_SET else CTAP2_ERR_PIN_AUTH_INVALID)
            else -> throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        }
    }

    private fun credentialIds(descriptors: List<*>?): List<ByteArray> = descriptors.orEmpty().mapNotNull {
        val descriptor = it as? Map<*, *> ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        if (descriptor["type"] == "public-key") descriptor.bytes("id") else null
    }

    private class CtapError(val status: Byte) : Exception(null, null, false, false)

    private companion object {
        fun Map<*, *>.required(key: Any): Any = this[key] ?: throw CtapError(CTAP2_ERR_MISSING_PARAMETER)

        fun Map<*, *>.bytes(key: Any) = required(key) as? ByteArray ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        fun Map<*, *>.string(key: Any) = required(key) as? String ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        fun Map<*, *>.map(key: Any) = required(key) as? Map<*, *> ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        fun Map<*, *>.list(key: Any) = required(key) as? List<*> ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)

        fun Map<*, *>.optionalString(key: Any) =
            this[key]?.let { it as? String ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE) }
        fun Map<*, *>.optionalMap(key: Any) =
            this[key]?.let { it as? Map<*, *> ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE) }
        fun Map<*, *>.optionalList(key: Any) =
            this[key]?.let { it as? List<*> ?: throw CtapError(CTAP2_ERR_CBOR_UNEXPECTED_TYPE) }
    }
}

/**
 * How long a request waits for the user. Browsers give up after a minute or two as well.
 */
const val USER_TIMEOUT_MS = 3 * 60 * 1000L
private const val MAX_CREDENTIAL_COUNT_IN_LIST = 64L
private const val MAX_CREDENTIAL_ID_LENGTH = 1024L

internal const val CMD_MAKE_CREDENTIAL: Byte = 0x01
internal const val CMD_GET_ASSERTION: Byte = 0x02
internal const val CMD_GET_INFO: Byte = 0x04
internal const val CMD_RESET: Byte = 0x07
internal const val CMD_GET_NEXT_ASSERTION: Byte = 0x08

internal const val CTAP2_OK: Byte = 0x00
internal const val CTAP1_ERR_INVALID_COMMAND: Byte = 0x01
internal const val CTAP1_ERR_INVALID_PARAMETER: Byte = 0x02
internal const val CTAP1_ERR_INVALID_LENGTH: Byte = 0x03
internal const val CTAP2_ERR_CBOR_UNEXPECTED_TYPE: Byte = 0x11
internal const val CTAP2_ERR_INVALID_CBOR: Byte = 0x12
internal const val CTAP2_ERR_MISSING_PARAMETER: Byte = 0x14
internal const val CTAP2_ERR_CREDENTIAL_EXCLUDED: Byte = 0x19
internal const val CTAP2_ERR_UNSUPPORTED_ALGORITHM: Byte = 0x26
internal const val CTAP2_ERR_OPERATION_DENIED: Byte = 0x27
internal const val CTAP2_ERR_UNSUPPORTED_OPTION: Byte = 0x2B
internal const val CTAP2_ERR_INVALID_OPTION: Byte = 0x2C
internal const val CTAP2_ERR_KEEPALIVE_CANCEL: Byte = 0x2D
internal const val CTAP2_ERR_NO_CREDENTIALS: Byte = 0x2E
internal const val CTAP2_ERR_USER_ACTION_TIMEOUT: Byte = 0x2F
internal const val CTAP2_ERR_NOT_ALLOWED: Byte = 0x30
internal const val CTAP2_ERR_PIN_AUTH_INVALID: Byte = 0x33
internal const val CTAP2_ERR_PIN_NOT_SET: Byte = 0x35
