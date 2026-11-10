// SupportedLanguagePlTest.kt
// PGPony Android, 4.8.0 RC9 (item 4f): Polish is in the language picker, a
// Polish device resolves to it, and values-pl covers every translatable
// string with the same format arguments and all four Polish plural forms.

package com.pgpony.android.i18n

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SupportedLanguagePlTest {

    @Test
    fun `Polish tags resolve to Polish`() {
        assertEquals(SupportedLanguage.PL, SupportedLanguage.resolve("pl"))
        assertEquals(SupportedLanguage.PL, SupportedLanguage.resolve("pl-PL"))
        assertEquals(SupportedLanguage.PL, SupportedLanguage.resolve("pl_PL"))
    }

    private val stringRe = Regex("""<string name="([^"]+)"([^>]*)>(.*?)</string>""", RegexOption.DOT_MATCHES_ALL)
    private val pluralsRe = Regex("""<plurals name="([^"]+)"[^>]*>(.*?)</plurals>""", RegexOption.DOT_MATCHES_ALL)
    private val itemRe = Regex("""<item quantity="([a-z]+)">(.*?)</item>""", RegexOption.DOT_MATCHES_ALL)
    private val argRe = Regex("""%(\d+\$)?[sd]""")

    private fun args(text: String) = argRe.findAll(text).map { it.value }.toSortedSet()

    // values/strings.xml carries example <string> lines inside its header comment.
    private fun read(path: String) =
        File(path).readText().replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")

    @Test
    fun `values-pl has every translatable string with the same format arguments`() {
        val en = read("src/main/res/values/strings.xml")
        val pl = read("src/main/res/values-pl/strings.xml")
        val plStrings = stringRe.findAll(pl).associate { it.groupValues[1] to it.groupValues[3] }
        for (m in stringRe.findAll(en)) {
            val (name, attrs, text) = m.destructured
            if (attrs.contains("translatable=\"false\"")) continue
            val translated = plStrings[name]
            assertTrue("$name is in values-pl", translated != null)
            assertEquals("format arguments of $name", args(text), args(translated!!))
        }
    }

    @Test
    fun `every Polish plural has one, few, many and other with the English arguments`() {
        val en = read("src/main/res/values/strings.xml")
        val pl = read("src/main/res/values-pl/strings.xml")
        val plPlurals = pluralsRe.findAll(pl).associate { it.groupValues[1] to it.groupValues[2] }
        for (m in pluralsRe.findAll(en)) {
            val name = m.groupValues[1]
            val enArgs = itemRe.findAll(m.groupValues[2]).flatMap { args(it.groupValues[2]) }.toSortedSet()
            val body = plPlurals[name]
            assertTrue("$name is in values-pl", body != null)
            val items = itemRe.findAll(body!!).associate { it.groupValues[1] to it.groupValues[2] }
            assertEquals("plural forms of $name", setOf("one", "few", "many", "other"), items.keys)
            for ((q, text) in items) {
                // A "one" form may spell the number out instead of using it.
                if (q == "one") assertTrue("arguments of $name/$q", enArgs.containsAll(args(text)))
                else assertEquals("arguments of $name/$q", enArgs, args(text))
            }
        }
    }
}
