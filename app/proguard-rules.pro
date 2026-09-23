# ── Bouncy Castle — OpenPGP (keep all crypto classes) ─────────────────
# CRITICAL: do not strip. Crypto correctness depends on this.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# ── Post-quantum composite (ML-KEM-768 + X25519) ─────────────────────
# The org.bouncycastle.** keep above already covers BC's ML-KEM (KEM),
# KMAC256, SHA3, and RFC-3394 AES key-wrap classes the composite path uses,
# and the com.pgpony.android.crypto.** keep below covers our pqc package.
# These explicit keeps document that dependency for the 4.0.0 PQC release and
# guard against any future narrowing of those wildcards. The composite
# session-key derivation is security-critical — keep it verbatim, unshrunk
# and unobfuscated.
-keep class com.pgpony.android.crypto.pqc.** { *; }
-keep class org.bouncycastle.pqc.** { *; }
-keep class org.bouncycastle.crypto.digests.SHA3Digest { *; }
-keep class org.bouncycastle.crypto.macs.KMAC { *; }

# ── PGPony app classes ────────────────────────────────────────────────
# 4.5.1 (Play vitals): the broad app-package keeps were removed to raise
# DEX-code optimization. App code is called directly, not by name, so R8 may
# shrink and obfuscate it. What still needs keeping is covered specifically:
# the composite PQ path above, Room entities/DAOs by their annotations below,
# Parcelables by the CREATOR rule, serializers by the kotlinx.serialization
# rules, and manifest-declared components (the OpenPGP service, activities)
# which R8 keeps automatically as entry points.

# ── OpenPGP API contract (org.openintents.openpgp) ────────────────────
# CRITICAL: do not rename. These classes cross a Binder boundary.
#
# Parcel marshalling writes the class NAME as a string. Client apps
# (Thunderbird for Android, K-9 Mail, Password Store, Conversations)
# ship their own copy of this contract under the same fully qualified
# names and resolve that string with Class.forName. If R8 renames our
# copy, the name on the wire no longer exists on the other side and
# the client dies with
#
#   android.os.BadParcelableException: ClassNotFoundException when
#   unmarshalling: <obfuscated name>
#
# thrown from Intent.getParcelableExtra on the CLIENT's main thread.
#
# This is not theoretical. 4.0.x shipped without these rules: R8
# renamed OpenPgpSignatureResult (-> W2.b in the shipped mapping,
# -> x6.g in a later build) and every release-build client crashed on
# decrypt, which is the path that reads the signature result. Encrypt
# survived because no custom parcelable is read back on that path.
# Debug builds skip R8 entirely, which is why assembleDebug provider
# testing never surfaced it.
#
# The breakage is bidirectional. AutocryptPeerUpdate travels
# client -> provider on ACTION_UPDATE_AUTOCRYPT_PEER, so an obfuscated
# name here also fails to unmarshal on OUR side of the boundary.
#
# Keep names AND members: android.os.Parcelable requires the CREATOR
# field to be found reflectively by name, and the AIDL-generated
# IOpenPgpService2.Stub / _Parcel classes live in this same package
# (without an explicit keep, proguard-android-optimize.txt merges the
# Stub into the anonymous subclass in PGPonyOpenPgpService and marks
# it R8$$REMOVED$$CLASS$$ in mapping.txt).
#
# Everything in this package is vendored API surface, not app logic,
# so keeping it whole costs almost nothing.
-keep class org.openintents.openpgp.** { *; }
-keep interface org.openintents.openpgp.** { *; }
-dontwarn org.openintents.openpgp.**

# Safety net for every other Parcelable that may cross a process
# boundary: the framework instantiates CREATOR reflectively, so it
# must never be renamed or stripped.
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

# ── Compose ──────────────────────────────────────────────────────────
# Compose ships its own consumer R8 rules; the whole-library keep was
# dropped in 4.5.1 to let R8 optimize (Play vitals).
-dontwarn androidx.compose.**

# ── Kotlinx Serialization (used by Ktor JSON) ────────────────────────
# Standard rules from kotlinx.serialization README.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

-keepclasseswithmembers class **.*$Companion {
    kotlinx.serialization.KSerializer serializer(...);
}
-if class **.*$Companion {
    kotlinx.serialization.KSerializer serializer(...);
}
-keepclasseswithmembers class <1>.<2> {
    <1>.<2>$Companion Companion;
}

# Keep all KSerializer implementations
-keep,includedescriptorclasses class * implements kotlinx.serialization.KSerializer { *; }

# ── Ktor / coroutines ────────────────────────────────────────────────
# Both ship consumer R8 rules; whole-library keeps dropped in 4.5.1.
-dontwarn io.ktor.**
-dontwarn kotlinx.coroutines.**

# ── CameraX (QR scanner) ─────────────────────────────────────────────
-dontwarn androidx.camera.**

# ── Biometric ────────────────────────────────────────────────────────
-dontwarn androidx.biometric.**

# ── Room ─────────────────────────────────────────────────────────────
# Most Room rules come from the runtime AAR, but explicit keeps for our
# entities prevent KSP-generated DAOs from going missing.
-keep class androidx.room.** { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }
-keep @androidx.room.Database class * { *; }

# ── EncryptedSharedPreferences (security-crypto) ─────────────────────
-keep class androidx.security.crypto.** { *; }
-dontwarn androidx.security.crypto.**

# ── R8 missing class warnings (annotations + optional logging) ───────
# Compile-time annotations and optional SLF4J binders not packaged at
# runtime. References come from Tink (via security-crypto) and similar.
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn javax.annotation.concurrent.**
-dontwarn org.slf4j.impl.**

# ── 4.6.0 (item 17.11): no debug or verbose logging in release ────────
# Release logcat carried looked-up email addresses from the key-server and
# WKD lookups (never key material or plaintext). Debug and verbose logging
# is compiled out of release builds; warnings and errors stay, and none of
# those carry an address.
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}
