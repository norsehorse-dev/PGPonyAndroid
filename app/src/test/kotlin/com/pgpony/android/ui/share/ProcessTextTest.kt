// ProcessTextTest.kt
// PGPony Android, 4.8.0 (#103)
//
// The text selection menu's Encrypt and Sign: which flow an intent asks for,
// whether the result replaces the selection or is shown in PGPony, which
// selections go to the Quick Action instead, and that the manifest's aliases
// match the names the activity reads.

package com.pgpony.android.ui.share

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SigningService
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class ProcessTextTest {

    private val svc = PGPCryptoService.shared
    private val k by lazy { svc.generateKeyPair("Select", "select@example.org", KeyAlgorithm.ED25519_CV25519, null) }
    private val pub by lazy { PGPPublicKeyRing(k.publicKeyData, BcKeyFingerprintCalculator()) }
    private val sec by lazy { PGPSecretKeyRing(k.privateKeyData, BcKeyFingerprintCalculator()) }

    // ── Mode from the intent ──────────────────────────────────────────

    @Test
    fun `each alias picks its own flow`() {
        assertEquals(ProcessText.Mode.ENCRYPT, ProcessText.modeFor(ProcessText.ACTION_PROCESS_TEXT, ProcessText.ALIAS_ENCRYPT))
        assertEquals(ProcessText.Mode.SIGN, ProcessText.modeFor(ProcessText.ACTION_PROCESS_TEXT, ProcessText.ALIAS_SIGN))
    }

    @Test
    fun `anything but a PROCESS_TEXT request to an alias runs nothing`() {
        assertNull(ProcessText.modeFor("android.intent.action.SEND", ProcessText.ALIAS_ENCRYPT))
        assertNull(ProcessText.modeFor(null, ProcessText.ALIAS_SIGN))
        assertNull(ProcessText.modeFor(ProcessText.ACTION_PROCESS_TEXT, "com.pgpony.android.ui.share.ProcessTextActivity"))
        assertNull(ProcessText.modeFor(ProcessText.ACTION_PROCESS_TEXT, null))
    }

    @Test
    fun `the action is the platform's`() {
        assertEquals("android.intent.action.PROCESS_TEXT", ProcessText.ACTION_PROCESS_TEXT)
    }

    // ── Result back or shown ──────────────────────────────────────────

    @Test
    fun `an editable field with a caller gets the result back`() {
        assertTrue(ProcessText.returnsResult(readOnly = false, hasCaller = true, resultLength = 900))
        assertTrue(ProcessText.returnsResult(false, true, ProcessText.RESULT_LIMIT_CHARS))
    }

    @Test
    fun `a read-only field, no caller or a huge result shows the result in PGPony`() {
        assertFalse(ProcessText.returnsResult(readOnly = true, hasCaller = true, resultLength = 900))
        assertFalse(ProcessText.returnsResult(readOnly = false, hasCaller = false, resultLength = 900))
        assertFalse(ProcessText.returnsResult(false, true, ProcessText.RESULT_LIMIT_CHARS + 1))
    }

    // ── Armor detection ───────────────────────────────────────────────

    @Test
    fun `plain text is encrypted or signed here`() {
        assertFalse(ProcessText.isPgpSelection("See you at eight"))
        assertFalse(ProcessText.isPgpSelection("The header is -----BEGIN PGP MESSAGE----- and then base64"))
    }

    @Test
    fun `an encrypted message goes to the Quick Action`() {
        val ct = String(svc.encrypt("secret".toByteArray(), listOf(pub)))
        assertTrue(ProcessText.isPgpSelection(ct))
        assertTrue(ProcessText.isPgpSelection("Reply below\n\n$ct\n"))
    }

    @Test
    fun `cleartext-signed and inline-signed text go to the Quick Action`() {
        assertTrue(ProcessText.isPgpSelection(SigningService.shared.signClear("hello", sec, null)))
        assertTrue(ProcessText.isPgpSelection(String(svc.sign("hello".toByteArray(), sec, ""))))
    }

    @Test
    fun `a key block goes to the Quick Action`() {
        assertTrue(ProcessText.isPgpSelection(svc.exportArmoredPublicKey(pub)))
    }

    // ── Manifest ──────────────────────────────────────────────────────

    @Test
    fun `the manifest's aliases are the names the activity reads`() {
        val source = sequenceOf(File("src/main/AndroidManifest.xml"), File("app/src/main/AndroidManifest.xml"))
            .first { it.isFile }
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val doc = factory.newDocumentBuilder().parse(source)
        val aliases = doc.getElementsByTagName("activity-alias").let { list ->
            (0 until list.length).map { list.item(it) as Element }
        }
        fun full(name: String) = if (name.startsWith(".")) "com.pgpony.android$name" else name
        val byName = aliases.associateBy { full(it.getAttributeNS(ANDROID, "name")) }
        for (alias in listOf(ProcessText.ALIAS_ENCRYPT, ProcessText.ALIAS_SIGN)) {
            val found = byName[alias]
            assertNotNull(alias, found)
            val e = found!!
            assertEquals("com.pgpony.android.ui.share.ProcessTextActivity", full(e.getAttributeNS(ANDROID, "targetActivity")))
            assertEquals("true", e.getAttributeNS(ANDROID, "exported"))
            assertTrue(e.getAttributeNS(ANDROID, "label").startsWith("@string/process_text_"))
            val actions = e.getElementsByTagName("action")
            assertEquals(ProcessText.ACTION_PROCESS_TEXT, (actions.item(0) as Element).getAttributeNS(ANDROID, "name"))
            val data = e.getElementsByTagName("data")
            assertEquals("text/plain", (data.item(0) as Element).getAttributeNS(ANDROID, "mimeType"))
        }
        // The result reaches the caller only from a standard activity in its task.
        val activities = doc.getElementsByTagName("activity").let { list ->
            (0 until list.length).map { list.item(it) as Element }
        }
        val target = activities.first { full(it.getAttributeNS(ANDROID, "name")) == "com.pgpony.android.ui.share.ProcessTextActivity" }
        assertFalse(target.hasAttributeNS(ANDROID, "launchMode"))
        assertFalse(target.hasAttributeNS(ANDROID, "taskAffinity"))
    }

    private companion object {
        const val ANDROID = "http://schemas.android.com/apk/res/android"
    }
}
