// ErrorText.kt
// PGPony Android, 4.6.2
//
// Error messages raised in the crypto, card, key store, backup and provider
// code are written in English, and the screens have been showing them as they
// are, so a user who picked another language still got English whenever
// something went wrong. Rewriting every throw site would touch reviewed crypto
// code and change the messages that the code itself and the unit tests match
// on, so those messages stay as they are. Instead, the places that DISPLAY an
// error pass it through here: each known English message is matched against a
// rule in ErrorTextRules and shown from its string resource in the user's
// language. Parts of a message that carry a nested message ("Storage failed:
// <reason>") are translated the same way. Text no rule knows (a library's own
// message, for instance) is shown unchanged, exactly as before.

package com.pgpony.android.i18n

import android.content.Context
import android.content.res.Configuration
import android.os.LocaleList
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatDelegate
import com.pgpony.android.PGPonyApp

object ErrorText {

    /** One known English message: [pattern] must match the whole message. */
    class Rule(pattern: String, @StringRes val resId: Int) {
        val regex = Regex(pattern, RegexOption.DOT_MATCHES_ALL)
    }

    /**
     * Prefixes the crypto layer puts in front of a message. A screen whose own
     * string already names the operation ("Decryption failed: %1$s") uses
     * [detail], which drops these so the words do not appear twice.
     */
    private val operationPrefixes = listOf(
        "Key generation failed: ",
        "Encryption failed: ",
        "Decryption failed: ",
        "Signing failed: ",
        "Verification failed: ",
        "Key import failed: ",
        "Key export failed: ",
        "Storage failed: ",
    )

    private const val MAX_DEPTH = 4

    /** [message] in the language of [context], or unchanged if no rule knows it. */
    fun localize(context: Context, message: String?): String? =
        message?.let { translate(context, it, 0) }

    /** Like [localize], after removing a leading operation prefix (see above). */
    fun detail(context: Context, message: String?): String? =
        message?.let { translate(context, stripPrefixes(it), 0) }

    /** [localize] for code without a Context at hand (ViewModels, services). */
    fun localize(message: String?): String? {
        val context = appContext() ?: return message
        return localize(context, message)
    }

    /** [detail] for code without a Context at hand (ViewModels, services). */
    fun detail(message: String?): String? {
        if (message == null) return null
        val context = appContext() ?: return stripPrefixes(message)
        return detail(context, message)
    }

    /** The rule that matches all of [message] and its captured parts, or null. */
    fun match(message: String): Pair<Rule, List<String>>? {
        for (rule in ErrorTextRules.all) {
            val m = rule.regex.matchEntire(message) ?: continue
            return rule to m.groupValues.drop(1)
        }
        return null
    }

    private fun stripPrefixes(message: String): String {
        var m = message
        while (true) {
            val p = operationPrefixes.firstOrNull { m.startsWith(it) } ?: return m
            m = m.removePrefix(p)
        }
    }

    private fun translate(context: Context, message: String, depth: Int): String {
        if (depth > MAX_DEPTH) return message
        val (rule, parts) = match(message) ?: return message
        val args = parts.map { translate(context, it, depth + 1) }
        return try {
            if (args.isEmpty()) context.getString(rule.resId)
            else context.getString(rule.resId, *args.toTypedArray())
        } catch (_: RuntimeException) {
            message
        }
    }

    /**
     * The application context in the language chosen in PGPony's language
     * picker. On Android 13 and later the system already applies the per-app
     * language to the application context; on older versions AppCompat only
     * applies it to activities, so the chosen locale is applied here. Null in
     * JVM unit tests, where no Application exists.
     */
    fun appContext(): Context? {
        val app: Context = try {
            PGPonyApp.instance
        } catch (_: UninitializedPropertyAccessException) {
            return null
        }
        val chosen = AppCompatDelegate.getApplicationLocales()
        if (chosen.isEmpty) return app
        val config = Configuration(app.resources.configuration)
        config.setLocales(LocaleList.forLanguageTags(chosen.toLanguageTags()))
        return app.createConfigurationContext(config)
    }
}

/** This throwable's message in the user's language (see [ErrorText]). */
fun Throwable.userMessage(context: Context): String? = ErrorText.localize(context, message)

/** This throwable's message in the user's language, without a Context. */
fun Throwable.userMessage(): String? = ErrorText.localize(message)
