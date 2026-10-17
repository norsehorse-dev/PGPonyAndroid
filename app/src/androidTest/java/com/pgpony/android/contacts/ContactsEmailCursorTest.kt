package com.pgpony.android.contacts

import android.content.ContentProvider
import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.provider.ContactsContract.CommonDataKinds.Email
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test

@SdkSuppress(minSdkVersion = 29)
class ContactsEmailCursorTest {
    private class EmailProvider(val cursor: MatrixCursor) : ContentProvider() {
        var queries = 0
        var arguments: Array<out String>? = null
        override fun onCreate() = true
        override fun query(uri: Uri,projection: Array<out String>?,selection: String?,
            selectionArgs: Array<out String>?,sortOrder: String?): Cursor {
            queries++
            arguments = selectionArgs
            return cursor
        }
        override fun getType(uri: Uri) = "vnd.android.cursor.dir/email_v2"
        override fun insert(uri: Uri,values: ContentValues?): Uri? = null
        override fun delete(uri: Uri,selection: String?,selectionArgs: Array<out String>?) = 0
        override fun update(uri: Uri,values: ContentValues?,selection: String?,selectionArgs: Array<out String>?) = 0
    }

    private fun service(provider: EmailProvider,authorized: Boolean = true): ContactsService {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        provider.attachInfo(context,ProviderInfo().apply { authority = "com.android.contacts" })
        val resolver = ContentResolver.wrap(provider)
        return ContactsService(object : ContextWrapper(context) {
            override fun getContentResolver() = resolver
            override fun checkPermission(permission: String,pid: Int,uid: Int): Int =
                if(authorized) PackageManager.PERMISSION_GRANTED else PackageManager.PERMISSION_DENIED
        })
    }

    @Test fun preservesCompleteResultAndNormalizesOnlyLookupArgument() {
        val cursor = MatrixCursor(arrayOf(Email.CONTACT_ID,Email.DISPLAY_NAME_PRIMARY,Email.ADDRESS,Email.PHOTO_URI))
        cursor.addRow(arrayOf("42","Ada","ada@example.org","content://photos/42"))
        val provider = EmailProvider(cursor)
        assertEquals(DeviceContact("42","Ada",listOf("ada@example.org"),"content://photos/42"),
            service(provider).findContactByEmail(" Ada@Example.ORG "))
        assertArrayEquals(arrayOf("ada@example.org"),provider.arguments)
        assertTrue(cursor.isClosed)
    }

    @Test fun missingRequiredIdentifierReturnsNullAndClosesCursor() {
        val cursor = MatrixCursor(arrayOf(Email.ADDRESS)).apply { addRow(arrayOf("ada@example.org")) }
        assertNull(service(EmailProvider(cursor)).findContactByEmail("ada@example.org"))
        assertTrue(cursor.isClosed)
    }

    @Test fun missingOptionalColumnsUseExistingFallbackValues() {
        val cursor = MatrixCursor(arrayOf(Email.CONTACT_ID)).apply { addRow(arrayOf("42")) }
        assertEquals(DeviceContact("42","",listOf("Ada@Example.org"),null),
            service(EmailProvider(cursor)).findContactByEmail("Ada@Example.org"))
        assertTrue(cursor.isClosed)
    }

    @Test fun nullOptionalValuesUseExistingFallbacksAndNullIdentifierReturnsNull() {
        val columns = arrayOf(Email.CONTACT_ID,Email.DISPLAY_NAME_PRIMARY,Email.ADDRESS,Email.PHOTO_URI)
        val optional = MatrixCursor(columns).apply { addRow(arrayOf("42",null,null,null)) }
        assertEquals(DeviceContact("42","",listOf("ada@example.org"),null),
            service(EmailProvider(optional)).findContactByEmail("ada@example.org"))
        val missingId = MatrixCursor(columns).apply { addRow(arrayOf(null,"Ada","ada@example.org",null)) }
        assertNull(service(EmailProvider(missingId)).findContactByEmail("ada@example.org"))
        assertTrue(optional.isClosed)
        assertTrue(missingId.isClosed)
    }

    @Test fun emptyResultsAreClosedAndBlankOrUnauthorizedLookupsDoNotQuery() {
        val empty = MatrixCursor(arrayOf(Email.CONTACT_ID))
        assertNull(service(EmailProvider(empty)).findContactByEmail("ada@example.org"))
        assertTrue(empty.isClosed)
        val blank = EmailProvider(MatrixCursor(arrayOf(Email.CONTACT_ID)))
        assertNull(service(blank).findContactByEmail(" "))
        assertEquals(0,blank.queries)
        val denied = EmailProvider(MatrixCursor(arrayOf(Email.CONTACT_ID)))
        assertNull(service(denied,false).findContactByEmail("ada@example.org"))
        assertEquals(0,denied.queries)
    }
}
