package com.pgpony.android.i18n

import android.content.Context
import android.content.res.Configuration
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.pgpony.android.R
import java.util.Locale
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises compiled resources so XML escapes, locale fallback and formatting are all checked. */
@RunWith(AndroidJUnit4::class)
class LocalizedErrorResourcesTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val argument = Regex("%([0-9]+)[$]s")

    private fun localized(locale: Locale): Context {
        val config = Configuration(context.resources.configuration).apply { setLocale(locale) }
        return context.createConfigurationContext(config)
    }

    @Test fun koreanErrorsDoNotFallBackToEnglishAndKeepEveryFormatArgument() {
        val english = localized(Locale.ENGLISH)
        val korean = localized(Locale.KOREAN)
        val errors = R.string::class.java.fields.filter { it.name.startsWith("err_") }
        assertTrue("The localized error catalogue must be present", errors.isNotEmpty())
        for (field in errors) {
            val id = field.getInt(null)
            val source = english.getString(id)
            val translated = korean.getString(id)
            assertNotEquals("Missing Korean translation: ${field.name}", source, translated)
            val expected = argument.findAll(source).map { it.groupValues[1].toInt() }.sorted().toList()
            val actual = argument.findAll(translated).map { it.groupValues[1].toInt() }.sorted().toList()
            assertEquals("Changed format arguments: ${field.name}", expected, actual)
            val args = Array<Any>(expected.maxOrNull() ?: 0) { "value${it + 1}" }
            val formatted = korean.getString(id, *args)
            assertFalse("Unexpanded argument: ${field.name}", argument.containsMatchIn(formatted))
        }
    }

}
