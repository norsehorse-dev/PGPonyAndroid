// SupportedLanguageKoTest.kt
// PGPony Android, 4.8.0 (item 4k): Korean is in the language picker and in
// locales_config.xml, and a Korean device resolves to it.

package com.pgpony.android.i18n

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SupportedLanguageKoTest {

    @Test
    fun `Korean tags resolve to Korean`() {
        assertEquals(SupportedLanguage.KO, SupportedLanguage.resolve("ko"))
        assertEquals(SupportedLanguage.KO, SupportedLanguage.resolve("ko-KR"))
        assertEquals(SupportedLanguage.KO, SupportedLanguage.resolve("ko_KR"))
    }

    @Test
    fun `every picker language is in locales_config and has a resource folder`() {
        val config = File("src/main/res/xml/locales_config.xml").readText()
        for (lang in SupportedLanguage.entries) {
            assertTrue("${lang.tag} is in locales_config.xml", config.contains("android:name=\"${lang.tag}\""))
            if (lang == SupportedLanguage.EN) continue
            val folder = when (lang.tag) {
                "pt-BR" -> "values-pt-rBR"
                "zh-Hans" -> "values-b+zh+Hans"
                else -> "values-${lang.tag}"
            }
            assertTrue("$folder exists", File("src/main/res/$folder/strings.xml").exists())
        }
    }
}
