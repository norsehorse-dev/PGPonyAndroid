// MimeBodyOnlyTest.kt
// PGPony Android 4.8.1 (#123): a PGP/MIME message with protected headers and a
// quoted-printable UTF-8 body. Pasted, it showed decoded; decrypted from a
// file, the result sheet showed the raw MIME (=2E, =E5=B8...) because the file
// path only parsed MIME to look for attachments. Both now show the body the
// parser decodes here.

package com.pgpony.android.crypto.mime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MimeBodyOnlyTest {

    private val message = (
        "Content-Transfer-Encoding: quoted-printable\r\n" +
            "Content-Type: text/plain;\r\n charset=utf-8; protected-headers=\"v1\"\r\n" +
            "Subject: Thanks for your work\r\n" +
            "\r\n" +
            "I hope I can help you improve the content better=2E\r\n" +
            "\r\n" +
            "=E5=B8=8C=E6=9C=9B=E6=88=91=E5=8F=AF=E4=BB=A5=E5=B8=AE=E5=8A=A9=E4=BD=A0=\r\n" +
            "=E6=9B=B4=E5=A5=BD=E7=9A=84=E5=AE=8C=E5=96=84=E5=86=85=E5=AE=B9=E3=80=82\r\n"
        ).toByteArray(Charsets.US_ASCII)

    @Test
    fun `a body-only message decodes its quoted-printable UTF-8 body`() {
        val parsed = MimeParser.parse(message)
        assertNotNull(parsed)
        assertFalse(parsed!!.hasAttachments)
        val body = requireNotNull(parsed.body)
        assertTrue(body, body.contains("I hope I can help you improve the content better."))
        assertTrue(body, body.contains("希望我可以帮助你更好的完善内容。"))
        assertFalse(body, body.contains("=2E"))
        assertFalse(body, body.contains("=E5"))
    }

    @Test
    fun `plain text that is not MIME is left alone`() {
        assertEquals(null, MimeParser.parse("just a note, not a message".toByteArray()))
    }
}
