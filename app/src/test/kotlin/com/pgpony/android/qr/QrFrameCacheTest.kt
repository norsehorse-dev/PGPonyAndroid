package com.pgpony.android.qr

import org.junit.Assert.*
import org.junit.Test

class QrFrameCacheTest {
    @Test fun cacheRetainsOnlyThreeFramesAndEvictsLeastRecentlyDisplayed() {
        val cache = QrFrameCache<Any>()
        val first = Any()
        assertSame(first, cache.get(0, 800) { first })
        cache.get(1, 800) { Any() }
        cache.get(2, 800) { Any() }
        assertSame(first, cache.get(0, 800) { error("cached frame must be reused") })
        cache.get(3, 800) { Any() }
        var reloaded = false
        cache.get(1, 800) { reloaded = true; Any() }
        assertTrue(reloaded)
        assertEquals(3, cache.size)
    }

    @Test fun physicalSizeIsPartOfCacheKeyAndClearDropsReferences() {
        val cache = QrFrameCache<Any>()
        val original = cache.get(0, 800) { Any() }
        assertNotSame(original, cache.get(0, 400) { Any() })
        cache.clear()
        assertEquals(0, cache.size)
        assertNotSame(original, cache.get(0, 800) { Any() })
    }
}
