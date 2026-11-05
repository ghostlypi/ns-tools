plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

/// arm64 for phones, x86_64 for the emulator. armeabi-v7a and x86 are dead weight for a
/// personal sideload and each adds ~3 MB of zstd + aes + ml-kem.
val abis = listOf("arm64-v8a", "x86_64")

android {
    namespace = "dev.ghostlypi.netdrop"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.ghostlypi.netdrop"
        // Android 10 is where exec-from-app-storage died, so nothing below it can work
        // anyway. It also avoids the ACCESS_FINE_LOCATION prompt that pre-33 mDNS needs.
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += abis }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Sideload only — debug signing is fine, no Play signing key needed.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    // UniFFI's generated Kotlin needs JNA with the `@aar` classifier on Android.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
}

// ---------------------------------------------------------------------------
// Rust integration — Phase 4. Commented out until the NDK is installed and
// `android/rust` compiles; see ../README.md for the toolchain prerequisites.
// ---------------------------------------------------------------------------
//
// val cargoBuild by tasks.registering(Exec::class) {
//     workingDir = file("../rust")
//     commandLine(
//         listOf("cargo", "ndk") +
//             abis.flatMap { listOf("-t", it) } +
//             listOf("-o", "$projectDir/src/main/jniLibs", "build", "--release")
//     )
// }
//
// val uniffiBindgen by tasks.registering(Exec::class) {
//     dependsOn(cargoBuild)
//     commandLine(
//         "cargo", "run", "-p", "netdrop-ffi", "--bin", "uniffi-bindgen",
//         "generate", "--library",
//         "../../target/aarch64-linux-android/release/libnetdrop_ffi.so",
//         "--language", "kotlin",
//         "--out-dir", "${layout.buildDirectory.get()}/generated/uniffi",
//     )
// }
//
// android.sourceSets["main"].java.srcDir("${layout.buildDirectory.get()}/generated/uniffi")
// tasks.named("preBuild") { dependsOn(uniffiBindgen) }
