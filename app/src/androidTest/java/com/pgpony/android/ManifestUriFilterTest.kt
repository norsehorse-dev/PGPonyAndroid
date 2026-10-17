package com.pgpony.android

import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.PatternMatcher
import android.provider.OpenableColumns
import com.pgpony.android.intent.IntentAction
import com.pgpony.android.intent.IntentHandler
import com.pgpony.android.intent.ShareIntentContent
import androidx.core.content.FileProvider
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.*
import org.junit.Test
import org.xmlpull.v1.XmlPullParser

/** Exercises Android's matcher using filters read from the installed, merged APK manifest. */
class ManifestUriFilterTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val resolver get() = context.contentResolver

    private fun filtersFor(activitySuffix: String): List<IntentFilter> {
        val filters = mutableListOf<IntentFilter>()
        var activity: String? = null
        var filter: IntentFilter? = null
        context.assets.openXmlResourceParser("AndroidManifest.xml").use { parser ->
            while(parser.eventType != XmlPullParser.END_DOCUMENT) {
                if(parser.eventType == XmlPullParser.START_TAG) {
                    when(parser.name) {
                        "activity" -> activity = parser.getAttributeValue(ANDROID,"name")
                        "intent-filter" -> if(activity?.endsWith(activitySuffix) == true) filter = IntentFilter()
                        "action" -> parser.getAttributeValue(ANDROID,"name")?.let { filter?.addAction(it) }
                        "category" -> parser.getAttributeValue(ANDROID,"name")?.let { filter?.addCategory(it) }
                        "data" -> filter?.let { current ->
                            parser.getAttributeValue(ANDROID,"scheme")?.let { current.addDataScheme(it) }
                            parser.getAttributeValue(ANDROID,"host")?.let {
                                current.addDataAuthority(it,parser.getAttributeValue(ANDROID,"port"))
                            }
                            parser.getAttributeValue(ANDROID,"mimeType")?.let { current.addDataType(it) }
                            parser.getAttributeValue(ANDROID,"path")?.let { current.addDataPath(it,PatternMatcher.PATTERN_LITERAL) }
                            parser.getAttributeValue(ANDROID,"pathPrefix")?.let { current.addDataPath(it,PatternMatcher.PATTERN_PREFIX) }
                            parser.getAttributeValue(ANDROID,"pathPattern")?.let { current.addDataPath(it,PatternMatcher.PATTERN_SIMPLE_GLOB) }
                        }
                    }
                } else if(parser.eventType == XmlPullParser.END_TAG) {
                    when(parser.name) {
                        "intent-filter" -> { filter?.let(filters::add); filter = null }
                        "activity" -> activity = null
                    }
                }
                parser.next()
            }
        }
        assertTrue("No merged manifest filters found for $activitySuffix",filters.isNotEmpty())
        return filters
    }

    private fun matches(activity: String,uri: String,mime: String?): Boolean {
        val intent = Intent(Intent.ACTION_VIEW).addCategory(Intent.CATEGORY_DEFAULT)
            .setDataAndType(Uri.parse(uri),mime)
        return filtersFor(activity).any { it.match(resolver,intent,true,"PGPonyUriFilterTest") >= 0 }
    }

    @Test fun genericContentTypesKeepProviderAndDocumentsUiPathsReachable() {
        val prefixes = listOf("content://com.example.files/export/",
            "content://com.android.externalstorage.documents/document/",
            "content:///export/")
        for(prefix in prefixes) for(mime in listOf("text/plain","application/octet-stream")) {
            for(document in listOf("msf%3A1042","primary%3ADownload%2Fpublic.asc","backup.pgpony","notes.txt")) {
                for(activity in listOf(".MainActivity",".ui.share.ShareTargetActivity")) {
                    assertTrue("$activity $prefix$document $mime",matches(activity,prefix+document,mime))
                }
            }
        }
    }

    @Test fun genericContentFiltersStillRejectUnrelatedMimeTypesAndSchemes() {
        for(activity in listOf(".MainActivity",".ui.share.ShareTargetActivity")) {
            assertFalse(matches(activity,"content://files/document/msf%3A1042","image/png"))
            assertFalse(matches(activity,"https://files/document/msf%3A1042","text/plain"))
        }
    }

    @Test fun existingTypedPgpAndMailViewFiltersKeepAcceptingOpaqueProviderPaths() {
        for(mime in listOf("application/pgp-encrypted","application/pgp-keys","application/pgp-signature","message/rfc822")) {
            assertTrue(mime,matches(".ui.share.ShareTargetActivity","content://files/document/opaque-id",mime))
            assertTrue(mime,matches(".ui.share.ShareTargetActivity","content://files/notes.txt",mime))
        }
    }

    @Test fun existingFileUriExtensionFiltersRemainAvailableWithoutMimeType() {
        for(prefix in listOf("file:///storage/emulated/0/Download/","file://localhost/export/")) {
            assertTrue(matches(".MainActivity",prefix+"backup.pgpony",null))
            assertFalse(matches(".MainActivity",prefix+"notes.txt",null))
            for(extension in listOf("asc","pgp","gpg","sig","eml")) {
                assertTrue(extension,matches(".ui.share.ShareTargetActivity",prefix+"key.$extension",null))
            }
            assertFalse(matches(".ui.share.ShareTargetActivity",prefix+"notes.txt",null))
        }
    }

    @Test fun resolvesRealFileProviderMimeTypesBeforeMatchingInstalledFilters() {
        val directory = File(context.cacheDir,"exports/manifest-uri-test").apply { mkdirs() }
        try {
            for(name in listOf("backup.pgpony","public.asc","message.gpg","signature.sig","message.eml","notes.txt")) {
                val file = File(directory,name).apply { writeText("Public intent-filter test fixture") }
                val uri = FileProvider.getUriForFile(context,context.packageName+".fileprovider",file)
                assertNotNull("Provider MIME missing for $name",resolver.getType(uri))
                val intent = Intent(Intent.ACTION_VIEW).addCategory(Intent.CATEGORY_DEFAULT).setData(uri)
                val activity = if(name.endsWith(".pgpony")) ".MainActivity" else ".ui.share.ShareTargetActivity"
                val accepted = filtersFor(activity).any { it.match(resolver,intent,true,"PGPonyUriFilterTest") >= 0 }
                assertTrue("$name (${resolver.getType(uri)})",accepted)
            }
        } finally { directory.deleteRecursively() }
    }

    @Test fun opaqueFileProviderDocumentsReachMetadataAndContentClassification() {
        val directory = File(context.cacheDir,"exports/manifest-opaque-uri-test").apply { mkdirs() }
        val publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nPublic routing fixture\n-----END PGP PUBLIC KEY BLOCK-----"
        val backup = "Opaque backup routing fixture".toByteArray()
        try {
            for((index,name) in listOf("public.asc","backup.pgpony").withIndex()) {
                val bytes = if(index == 0) publicKey.toByteArray() else backup
                val file = File(directory,"msf-"+(1042+index)).apply { writeBytes(bytes) }
                val uri = FileProvider.getUriForFile(context,context.packageName+".fileprovider",file,name)
                assertFalse(uri.lastPathSegment.orEmpty().contains('.'))
                assertEquals("application/octet-stream",resolver.getType(uri))
                resolver.query(uri,arrayOf(OpenableColumns.DISPLAY_NAME),null,null,null)!!.use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    assertEquals(name,cursor.getString(cursor.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)))
                }
                val intent = Intent(Intent.ACTION_VIEW).addCategory(Intent.CATEGORY_DEFAULT).setData(uri)
                val activity = if(index == 0) ".ui.share.ShareTargetActivity" else ".MainActivity"
                assertTrue("Opaque document with DISPLAY_NAME=$name must reach $activity",
                    filtersFor(activity).any { it.match(resolver,intent,true,"PGPonyUriFilterTest") >= 0 })
                if(index == 0) {
                    // Routing recognizes armor; key parsing and import happen after this boundary.
                    assertEquals(IntentAction.ImportKey(publicKey),IntentHandler.process(intent,resolver))
                    val classified = IntentHandler.classifyShareIntent(intent,resolver)
                    assertTrue(classified is ShareIntentContent.PgpFile)
                    classified as ShareIntentContent.PgpFile
                    assertEquals(name,classified.filename)
                    assertTrue(classified.looksLikePgpKey)
                } else {
                    val action = IntentHandler.process(intent,resolver)
                    assertTrue(action is IntentAction.RestoreBackup)
                    assertArrayEquals(backup,(action as IntentAction.RestoreBackup).data)
                }
            }
        } finally { directory.deleteRecursively() }
    }

    private companion object { const val ANDROID = "http://schemas.android.com/apk/res/android" }
}
