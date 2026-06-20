import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.google.devtools.ksp")
}

// Load signing properties from keystore.properties at project root.
// File is gitignored — see .gitignore. Never commit it.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

android {
    namespace = "com.pgpony.android"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.pgpony.android"
        minSdk = 26
        targetSdk = 35
        // A16 — Bump for v1.0 Play Store launch.
        //
        // versionCode jumps from 7 (last shipped: A1, v1.5.0) to 100. The
        // big jump leaves room to slot in future hotfix builds at 101/102/…
        // without colliding with anything historical, and matches the
        // parity plan's "Bump versionCode to 100" directive verbatim.
        //
        // versionName follows the iOS lineage: 1.15.0 corresponds to
        // iOS PGPony v4.1 plus the full v5.0 feature set (A2–A15 Android
        // ports). Subsequent Android-only fixes can use 1.15.1, 1.15.2,
        // etc., while the next major iOS-parity drop would bump to 1.16.0.
        // v2.0.0 — hardware security key release. Adds full OpenPGP
        // smartcard / NFC support (decrypt, sign, encrypt-and-sign,
        // expiration editing, signature verification) validated across
        // Token2 and YubiKey, plus card-key support in the decrypt picker
        // and Exchange, discoverable PIN change, and clear-tab actions.
        // v2.1.1 — onboarding key generation can now produce an RFC 9580
        // v6 key (Ed25519 v4 / v6 chooser on the first-key form), matching
        // the iOS onboarding v6 option.
        // v2.1.2 — Decrypt tab "Decrypt With" searchable key picker
        // (hardware keys pinned, most-used default, usage tracking via Room
        // migration 3->4) and a prominent "Paste from Clipboard" button on
        // the Import, Encrypt, and Decrypt tabs.
        // v3.0.0 — public store release. Folds in on-card key generation,
        // admin-PIN lifecycle, the decrypt integrity-verification security
        // fix, Password Store read-only support, the open-source crypto core,
        // and the Phase E polish (version display, More from NorseHorse,
        // Encrypt recipient dropdown). versionCode jumps to 200 to leave the
        // 1xx band for the 2.x dev line.
        versionCode = 202
        versionName = "3.0.2"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // Apply signing config only if keystore.properties exists.
            // For local debug release builds without keys, fall back to debug signing.
            signingConfig = if (keystorePropertiesFile.exists()) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
            isMinifyEnabled = true
            // Disable AGP VCS info embedding so the release APK is byte-identical
            // regardless of which working tree it is built from. Without this, the
            // APK contains META-INF/version-control-info.textproto with a git commit
            // reference, which breaks F-Droid reproducible builds when the developer
            // build tree and the F-Droid clone resolve VCS state differently.
            vcsInfo.include = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    // ── Distribution flavors ────────────────────────────────────────────
    // play  → Google Play. Keeps the Play In-App Review dependency and the
    //         play-flavor RateAppHelper. Build / upload with playRelease.
    // foss  → F-Droid / IzzyOnDroid / direct APK. No Google Play deps. Uses
    //         the foss-flavor RateAppHelper. Build with fossRelease.
    flavorDimensions += "distribution"
    productFlavors {
        create("play") {
            dimension = "distribution"
        }
        create("foss") {
            dimension = "distribution"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }

    // FD3: drop the Google-signed dependency-metadata blob from build
    // outputs. It is opaque (only Google can read it), so F-Droid and
    // IzzyOnDroid prefer it gone. Removing it keeps the FOSS APK fully
    // transparent and has no effect on app behavior.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}
dependencies {
    // ── Bouncy Castle — OpenPGP ──────────────────────────────────────────
    //
    // V6-0 (RFC 9580 plan): bumped 1.78.1 → 1.84.
    //   - The v6 signature scheme and Argon2 PBE/S2K both landed in 1.79;
    //     1.78.1 predates them, so the crypto layer's existing comments
    //     claiming SEIPDv2 + Argon2id were unbacked on the old jar.
    //   - The native v6 key-pair generator API (Ed25519/X25519/Ed448/X448)
    //     matured by 1.84 — needed for v6 key generation in V6-3.
    //   - 1.84 closes CVE-2026-3505 (unbounded PGP AEAD chunk size →
    //     pre-auth resource exhaustion), which sits on the AEAD path this
    //     v6 work expands.
    // bcprov and bcpg are version-locked together. ProGuard already keeps
    // org.bouncycastle.** wholesale, so no keep-rule change is required.
    implementation("org.bouncycastle:bcprov-jdk18on:1.84")
    implementation("org.bouncycastle:bcpg-jdk18on:1.84")
    // ── Jetpack Compose ─────────────────────────────────────────────────
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    debugImplementation("androidx.compose.ui:ui-tooling")
    // ── Room (SwiftData equivalent) ─────────────────────────────────────
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")
    // ── DataStore (Preferences) ─────────────────────────────────────────
    //
    // Backs the customizable PGP armor "Comment:" header setting (toggle
    // + custom string). First DataStore-backed pref in the app; the rest
    // of Settings still uses SharedPreferences. See ArmorCommentSettings.
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("androidx.documentfile:documentfile:1.0.1")
    // ── Ktor (HTTP client for key server) ───────────────────────────────
    implementation("io.ktor:ktor-client-android:2.3.12")
    implementation("io.ktor:ktor-client-content-negotiation:2.3.12")
    implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.12")
    // Note: kotlinx-serialization-json comes in transitively via ktor-
    // serialization-kotlinx-json above. The serialization GRADLE plugin
    // is applied in the plugins{} block to enable @Serializable code
    // generation; no separate runtime dep is needed.
    // ── Google Play Billing — REMOVED for v1.0.0 (monetization restricted ─
    //     until Nov 2026). Re-add when ready:
    //     implementation("com.android.billingclient:billing-ktx:7.1.1")
    // ── ZXing (QR codes) ────────────────────────────────────────────────
    implementation("com.google.zxing:core:3.5.3")
    // ── CameraX (QR scanner) ────────────────────────────────────────────
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")
    // ── Biometric ───────────────────────────────────────────────────────
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    // ── AndroidX Core ───────────────────────────────────────────────────
    implementation("androidx.core:core-ktx:1.15.0")
    // ── AndroidX AppCompat — per-app language preferences API ───────────
    //
    // Added in A14 Picker phase. AppCompat is the canonical owner of
    // per-app locale state on Android. On API 33+ it delegates to the
    // platform LocaleManager; on API 26–32 it persists via its own
    // AppLocalesMetadataHolderService (declared in AndroidManifest.xml).
    //
    // We don't actually use any AppCompat themes, AppCompatActivity-only
    // widgets, or the AppCompat resource overlay — we use only the
    // AppCompatDelegate.setApplicationLocales() static method. But
    // pulling in the library is necessary for the Activity recreation
    // on locale change to fire correctly on older API levels.
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // ── In-App Review (Play Store rating prompt) — PLAY FLAVOR ONLY ─────
    //     Scoped to the play source set so the foss flavor (F-Droid /
    //     IzzyOnDroid / direct APK) carries no Google Play dependency. The
    //     foss flavor supplies its own RateAppHelper in src/foss that opens
    //     the public listing instead of the Play in-app review sheet.
    "playImplementation"("com.google.android.play:review-ktx:2.0.2")
    // ── Chrome Custom Tabs (open web links cleanly) ─────────────────────
    implementation("androidx.browser:browser:1.8.0")
    // ── Drag-to-reorder for the keyring (manual sort mode) ──────────────
    implementation("sh.calvin.reorderable:reorderable:2.4.0")
    // ── Testing ─────────────────────────────────────────────────────────
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.12.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
