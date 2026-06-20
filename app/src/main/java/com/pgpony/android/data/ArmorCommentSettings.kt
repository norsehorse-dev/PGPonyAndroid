// ArmorCommentSettings.kt
// PGPony Android
//
// User setting for the "Comment:" header embedded in ASCII-armored PGP
// output (encrypt / sign / encrypt-and-sign). The user can keep the
// default, write their own, or remove the comment entirely.
//
// Persistence is via Jetpack DataStore (Preferences), so both the
// toggle state and the custom string survive an app restart. This is
// the first DataStore-backed setting in the app; the rest of Settings
// still uses SharedPreferences and is intentionally left untouched.
//
// Three pieces live here:
//
//   1. ArmorCommentDefaults — the default string and the length cap.
//   2. ArmorCommentValidator — a pure, unit-testable function that
//      turns the raw (toggle, text) pair into the exact value that
//      will be written as "Comment: <value>", or null when no Comment
//      header should be written at all.
//   3. ArmorCommentHeader — a process-wide @Volatile cache that the
//      crypto layer reads synchronously when constructing an
//      ArmoredOutputStream. DataStore reads are asynchronous (Flow),
//      but the crypto path is synchronous, so we keep the latest
//      validated value in memory. The cache is seeded to the default
//      string and kept fresh by ArmorCommentStore.startCaching (called
//      from PGPonyApp.onCreate) plus an immediate write on every
//      Settings change. This mirrors the existing ThemeState.current /
//      LanguageState.current "observable global seeded at startup"
//      pattern already used in this codebase.
//
// SCOPE NOTE: this setting only affects message-style armored output
// (encrypt, sign, encrypt-and-sign). Exported public/secret keys are
// deliberately kept comment-free — see the clean-armor helpers in
// PGPCryptoService.kt. The export path never reads this setting.

package com.pgpony.android.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

// ── DataStore handle ───────────────────────────────────────────────────
//
// preferencesDataStore must be declared once as a top-level Context
// extension. The backing file is app-private (filesDir/datastore).
private val Context.armorCommentDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "armor_comment_settings"
)

// ── Defaults ───────────────────────────────────────────────────────────

object ArmorCommentDefaults {
    /**
     * Default Comment text. Matches the PGPony brand and the canonical
     * domain (pgpony.app). Embedded as: "Comment: PGPony - PGPony.app".
     */
    const val DEFAULT_COMMENT: String = "PGPony - PGPony.app"

    /** Hard cap on the embedded comment length, in characters. */
    const val MAX_LENGTH: Int = 80
}

// ── Validation ─────────────────────────────────────────────────────────

object ArmorCommentValidator {

    /**
     * Sanitize a raw user string into something that can NEVER produce a
     * malformed armor header line. Applied before the value is written
     * and before it is shown in the live preview, so the preview always
     * matches the bytes that will actually be embedded.
     *
     * Rules (in order):
     *   1. Force a single line: drop every CR and LF.
     *   2. Drop every other control character (tab, NUL, etc.) so the
     *      header can't contain anything non-printable.
     *   3. Strip any leading ':' characters (and surrounding leading
     *      whitespace). A value that started with ':' could otherwise be
     *      misread when a parser splits "Name: value" on the first colon.
     *   4. Trim leading/trailing whitespace.
     *   5. Cap at MAX_LENGTH characters, taking care not to split a
     *      Unicode surrogate pair, then trim any trailing space left by
     *      the cut.
     *
     * The result may be empty — callers treat empty as "no header".
     */
    fun sanitize(raw: String): String {
        // 1 + 2: remove CR, LF, and all other ISO control characters.
        val printable = raw.filterNot { it == '\r' || it == '\n' || it.isISOControl() }

        // 3: strip leading colons and the whitespace around them.
        var s = printable.trimStart()
        while (s.startsWith(":")) {
            s = s.removePrefix(":").trimStart()
        }

        // 4: trim both ends.
        s = s.trim()

        // 5: cap length without splitting a surrogate pair.
        if (s.length > ArmorCommentDefaults.MAX_LENGTH) {
            var cut = s.substring(0, ArmorCommentDefaults.MAX_LENGTH)
            if (cut.isNotEmpty() && Character.isHighSurrogate(cut.last())) {
                cut = cut.dropLast(1)
            }
            s = cut.trimEnd()
        }

        return s
    }

    /**
     * Resolve the (toggle, text) pair into the final Comment value, or
     * null when no Comment header should be written.
     *
     *   - Toggle OFF                         -> null (no header)
     *   - Toggle ON but empty after sanitize -> null (no header)
     *   - Toggle ON with content             -> the sanitized value
     */
    fun validate(include: Boolean, raw: String): String? {
        if (!include) return null
        val s = sanitize(raw)
        return s.ifEmpty { null }
    }
}

// ── Synchronous cache read by the crypto layer ─────────────────────────

object ArmorCommentHeader {
    /**
     * The validated Comment value to embed in message-style armored
     * output, or null for "no Comment header". Seeded to the default so
     * any encryption that happens before DataStore has been read still
     * gets a sensible value. Kept fresh by ArmorCommentStore.
     *
     * @Volatile because the crypto path may run on a different thread
     * from the DataStore collector / Settings writer.
     */
    @Volatile
    var current: String? = ArmorCommentDefaults.DEFAULT_COMMENT
}

// ── DataStore wrapper ──────────────────────────────────────────────────

class ArmorCommentStore private constructor(context: Context) {

    private val appContext = context.applicationContext
    private val ds = appContext.armorCommentDataStore

    /** Toggle state. Default ON. */
    val includeFlow: Flow<Boolean> = ds.data.map { prefs ->
        prefs[KEY_INCLUDE] ?: true
    }

    /** Raw (un-sanitized) custom string. Default = the default comment. */
    val textFlow: Flow<String> = ds.data.map { prefs ->
        prefs[KEY_TEXT] ?: ArmorCommentDefaults.DEFAULT_COMMENT
    }

    /** Persist the toggle and immediately refresh the crypto cache. */
    suspend fun setInclude(enabled: Boolean) {
        ds.edit { it[KEY_INCLUDE] = enabled }
        recache()
    }

    /** Persist the raw string and immediately refresh the crypto cache. */
    suspend fun setText(text: String) {
        ds.edit { it[KEY_TEXT] = text }
        recache()
    }

    /** One-shot read of the current (toggle, raw text) pair. */
    suspend fun snapshot(): Pair<Boolean, String> {
        val prefs = ds.data.first()
        return (prefs[KEY_INCLUDE] ?: true) to
                (prefs[KEY_TEXT] ?: ArmorCommentDefaults.DEFAULT_COMMENT)
    }

    /**
     * Re-read persisted values and push the validated result into the
     * synchronous cache. Called right after a write so the crypto layer
     * sees the change without waiting for the Flow collector.
     */
    private suspend fun recache() {
        val (include, text) = snapshot()
        ArmorCommentHeader.current = ArmorCommentValidator.validate(include, text)
    }

    /**
     * Start mirroring DataStore into ArmorCommentHeader.current. Call
     * once from PGPonyApp.onCreate with the process-scoped coroutine
     * scope. Survives app restart because it re-reads the persisted
     * DataStore on every cold start.
     */
    fun startCaching(scope: CoroutineScope) {
        scope.launch {
            combine(includeFlow, textFlow) { include, text ->
                ArmorCommentValidator.validate(include, text)
            }.collect { validated ->
                ArmorCommentHeader.current = validated
            }
        }
    }

    companion object {
        private val KEY_INCLUDE = booleanPreferencesKey("armor_comment_include")
        private val KEY_TEXT = stringPreferencesKey("armor_comment_text")

        @Volatile
        private var INSTANCE: ArmorCommentStore? = null

        /** Process-wide singleton so Settings and the app share one store. */
        fun get(context: Context): ArmorCommentStore =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: ArmorCommentStore(context).also { INSTANCE = it }
            }
    }
}
