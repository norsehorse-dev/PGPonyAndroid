# ── Bouncy Castle — OpenPGP (keep all crypto classes) ─────────────────
# CRITICAL: do not strip. Crypto correctness depends on this.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# ── PGPony app classes that crypto / Room / network code touches ──────
-keep class com.pgpony.android.crypto.** { *; }
-keep class com.pgpony.android.data.** { *; }
-keep class com.pgpony.android.network.** { *; }

# ── Compose ──────────────────────────────────────────────────────────
# Compose's own consumer ProGuard rules cover most of this, but the
# explicit keep guards against future BOM changes that loosen things.
-keep class androidx.compose.** { *; }
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

# ── Ktor ─────────────────────────────────────────────────────────────
-keep class io.ktor.** { *; }
-dontwarn io.ktor.**
-keep class kotlinx.coroutines.** { *; }
-dontwarn kotlinx.coroutines.**

# ── CameraX (QR scanner) ─────────────────────────────────────────────
-keep class androidx.camera.** { *; }
-dontwarn androidx.camera.**

# ── Biometric ────────────────────────────────────────────────────────
-keep class androidx.biometric.** { *; }
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
