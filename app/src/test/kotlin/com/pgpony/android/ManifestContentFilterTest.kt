package com.pgpony.android

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class ManifestContentFilterTest {
    @Test fun genericContentFiltersKeepOpaqueDocumentIdsReachable() {
        val source = sequenceOf(File("src/main/AndroidManifest.xml"),File("app/src/main/AndroidManifest.xml"))
            .first { it.isFile }
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val filters = factory.newDocumentBuilder().parse(source).getElementsByTagName("intent-filter")
        var genericContentFilters = 0
        for(index in 0 until filters.length) {
            val filter = filters.item(index) as Element
            val data = filter.getElementsByTagName("data")
            val entries = (0 until data.length).map { data.item(it) as Element }
            if(entries.any { it.getAttributeNS(ANDROID,"scheme") == "content" } &&
                entries.any { it.getAttributeNS(ANDROID,"mimeType") in GENERIC_TYPES }) {
                genericContentFilters++
                assertEquals(GENERIC_TYPES,entries.map { it.getAttributeNS(ANDROID,"mimeType") }
                    .filter { it.isNotEmpty() }.toSet())
                assertTrue("Provider display names need not appear in the URI path",
                    entries.none { entry -> PATH_ATTRIBUTES.any { entry.hasAttributeNS(ANDROID,it) } })
                assertTrue("Generic content filters must remain independent of provider authorities",
                    entries.none { it.hasAttributeNS(ANDROID,"host") })
            }
        }
        assertEquals(2,genericContentFilters)
    }

    private companion object {
        const val ANDROID = "http://schemas.android.com/apk/res/android"
        val GENERIC_TYPES = setOf("text/plain","application/octet-stream")
        val PATH_ATTRIBUTES = listOf("path","pathPrefix","pathPattern","pathAdvancedPattern","pathSuffix")
    }
}
