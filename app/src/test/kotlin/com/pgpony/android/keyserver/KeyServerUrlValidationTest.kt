// KeyServerUrlValidationTest.kt
// PGPony Android — 4.5.0 (item 6 / #55): custom key server URL validation.
//
// KeyServerDirectory.normalizeBaseUrl is the gate for user-entered key server
// URLs. It defaults a missing scheme to https, keeps only scheme://host[:port],
// accepts hkps/hkp (mapping them to https/http), and rejects anything else.

package com.pgpony.android.keyserver

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class KeyServerUrlValidationTest {

    private fun norm(s: String) = KeyServerDirectory.normalizeBaseUrl(s)

    @Test
    fun `bare host defaults to https`() {
        assertEquals("https://keys.example.org", norm("keys.example.org"))
    }

    @Test
    fun `explicit https is kept`() {
        assertEquals("https://keys.example.org", norm("https://keys.example.org"))
    }

    @Test
    fun `path and trailing slash are stripped`() {
        assertEquals("https://keys.example.org", norm("https://keys.example.org/"))
        assertEquals("https://keys.example.org", norm("https://keys.example.org/vks/v1"))
    }

    @Test
    fun `explicit http and port are preserved`() {
        assertEquals("http://keys.example.org:11371", norm("http://keys.example.org:11371"))
    }

    @Test
    fun `a dotless host is allowed only with an explicit port`() {
        assertEquals("https://localhost:11371", norm("localhost:11371"))
        assertNull(norm("localhost"))
    }

    @Test
    fun `hkps maps to https`() {
        assertEquals("https://keys.example.org", norm("hkps://keys.example.org"))
        assertEquals("https://keys.example.org:8443", norm("hkps://keys.example.org:8443"))
    }

    @Test
    fun `hkp maps to http on the default hkp port`() {
        assertEquals("http://keys.example.org:11371", norm("hkp://keys.example.org"))
        assertEquals("http://keys.example.org:11372", norm("hkp://keys.example.org:11372"))
    }

    @Test
    fun `unknown schemes and junk are rejected`() {
        assertNull(norm("ftp://keys.example.org"))
        assertNull(norm("gopher://keys.example.org"))
        assertNull(norm("   "))
        assertNull(norm(""))
        assertNull(norm("not a url"))
    }

    @Test
    fun `whitespace is trimmed`() {
        assertEquals("https://keys.example.org", norm("  keys.example.org  "))
    }
}
