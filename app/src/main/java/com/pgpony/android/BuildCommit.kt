// BuildCommit.kt
// PGPony Android, 4.8.0 RC8 (#114): the build's git commit as shown to people.
//
// app/build.gradle.kts writes HEAD's full hash into BuildConfig.GIT_COMMIT, or
// an empty string when the build had no git. About shows the first seven
// characters next to the version, so a tester can tell which RC is installed,
// and the feedback email carries the same. Pure Kotlin for the unit test.

package com.pgpony.android

object BuildCommit {

    /** Characters shown: enough to tell the RCs of one release apart. */
    const val SHORT_LENGTH = 7

    private val FULL = Regex("[0-9a-f]{40}|[0-9a-f]{64}")

    /** The short hash of [full], or an empty string when [full] is not a commit hash. */
    fun short(full: String): String = if (FULL.matches(full)) full.take(SHORT_LENGTH) else ""

    /** "4.8.0 (1a2b3c4)", or [versionName] alone when there is no commit. */
    fun versionLabel(versionName: String, full: String): String =
        short(full).let { if (it.isEmpty()) versionName else "$versionName ($it)" }
}
