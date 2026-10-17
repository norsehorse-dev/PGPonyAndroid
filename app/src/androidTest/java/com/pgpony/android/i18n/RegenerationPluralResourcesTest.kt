package com.pgpony.android.i18n

import android.content.Context
import android.content.res.Configuration
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.pgpony.android.R
import java.util.Locale
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RegenerationPluralResourcesTest {
    @Test fun frenchAndBrazilianPortugueseCountsRemainVisibleForZeroAndOne() {
        val context: Context = ApplicationProvider.getApplicationContext()
        // CLDR selects 'one' for both 0 and 1 in these locales; keep the actual count visible.
        for (locale in listOf(Locale.FRENCH, Locale("pt", "BR"))) {
            val config = Configuration(context.resources.configuration).apply { setLocale(locale) }
            val resources = context.createConfigurationContext(config).resources
            for (count in listOf(0, 1, 2, 11)) {
                val message = resources.getQuantityString(R.plurals.keyring_regen_hint_title, count, count)
                assertTrue("Missing count $count for $locale: $message", message.contains(count.toString()))
            }
        }
    }
}
