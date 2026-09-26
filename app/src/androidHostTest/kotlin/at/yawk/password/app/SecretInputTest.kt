package at.yawk.password.app

import android.text.InputType
import android.view.inputmethod.EditorInfo
import kotlin.test.Test
import kotlin.test.assertEquals

class SecretInputTest {
    @Test
    fun textGetsNoSuggestionsAndNoLearning() {
        val info = EditorInfo()
        info.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        info.imeOptions = EditorInfo.IME_ACTION_NEXT
        addSecretFlags(info)
        assertEquals(
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS,
            info.inputType,
        )
        assertEquals(EditorInfo.IME_ACTION_NEXT or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING, info.imeOptions)
    }

    @Test
    fun passwordKeepsItsType() {
        val info = EditorInfo()
        info.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        addSecretFlags(info)
        assertEquals(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING, info.imeOptions)

        // not text: only the IME flag
        val number = EditorInfo()
        number.inputType = InputType.TYPE_CLASS_NUMBER
        addSecretFlags(number)
        assertEquals(InputType.TYPE_CLASS_NUMBER, number.inputType)
    }
}
