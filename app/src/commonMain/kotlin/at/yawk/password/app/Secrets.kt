package at.yawk.password.app

import at.yawk.password.client.PasswordStore
import at.yawk.password.model.PasswordEntry
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.Collator

/**
 * Shown instead of the first line (the password) of an entry until it is revealed.
 */
const val PASSWORD_MASK = "••••••••••••"

private const val GENERATOR_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!@#%+="
private const val GENERATED_LENGTH = 24

private val random = SecureRandom()

/**
 * UTF-8 encode a password without going through a [String], so the caller can wipe the result. Malformed input is
 * replaced by `?` like [String.toByteArray] does, so the derived keys match those of the old GUI.
 */
fun encodePassword(password: CharSequence): ByteArray {
    val encoder = Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
    val buffer = encoder.encode(CharBuffer.wrap(password))
    val bytes = ByteArray(buffer.remaining())
    buffer.get(bytes)
    if (buffer.hasArray()) {
        buffer.array().fill(0)
    }
    return bytes
}

fun ByteArray.wipe() = fill(0)

fun constantTimeEquals(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)

/**
 * The entries whose name contains [query] (case-insensitive), sorted by name.
 */
fun filterEntries(entries: List<PasswordEntry>, query: String): List<PasswordEntry> {
    val collator = Collator.getInstance().apply { strength = Collator.SECONDARY }
    return entries
        .filter { it.name.orEmpty().contains(query, ignoreCase = true) }
        .sortedWith { a, b -> collator.compare(a.name.orEmpty(), b.name.orEmpty()) }
}

/**
 * The value as shown when not revealed: the first line masked, the rest as is.
 */
fun maskedValue(value: String?): String {
    val v = value.orEmpty()
    return PASSWORD_MASK + v.substring(PasswordStore.firstLine(v).length)
}

/**
 * Replace the first line of [value] with a new random password.
 */
fun withGeneratedPassword(value: String): String {
    val password = buildString(GENERATED_LENGTH) {
        repeat(GENERATED_LENGTH) { append(GENERATOR_ALPHABET[random.nextInt(GENERATOR_ALPHABET.length)]) }
    }
    return password + value.substring(PasswordStore.firstLine(value).length)
}
