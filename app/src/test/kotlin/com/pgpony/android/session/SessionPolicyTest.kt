// SessionPolicyTest.kt
// PGPony Android 4.6.3 (#15): the stored session duration is read back only as
// a value the policy offers, and anything else falls through to the default.
// The cross-process behavior itself is a device check (see PLANNING_4.6.3.md).

package com.pgpony.android.session

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SessionPolicyTest {

    @Test
    fun parse_acceptsEveryOfferedDuration() {
        assertEquals(60, SessionPolicy.parse("60"))
        assertEquals(300, SessionPolicy.parse("300\n"))
        assertEquals(3600, SessionPolicy.parse(" 3600 "))
        assertEquals(SessionPolicy.DURATION_UNTIL_CLEARED, SessionPolicy.parse("-1"))
        assertEquals(SessionPolicy.DURATION_UNTIL_LOCKED, SessionPolicy.parse("-2"))
    }

    @Test
    fun parse_rejectsWhatThePolicyNeverWrites() {
        assertNull(SessionPolicy.parse(null))
        assertNull(SessionPolicy.parse(""))
        assertNull(SessionPolicy.parse("0"))
        assertNull(SessionPolicy.parse("-3"))
        assertNull(SessionPolicy.parse("five minutes"))
    }

    @Test
    fun withoutAnAppContext_theDefaultApplies() {
        // Pure JVM: PGPonyApp.instance is not initialized, so neither the file
        // nor the preferences can be read.
        assertEquals(SessionPolicy.DEFAULT_DURATION_SEC, SessionPolicy.durationSec())
    }
}
