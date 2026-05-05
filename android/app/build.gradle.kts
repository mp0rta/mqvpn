plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.dagger.hilt.android")
    id("com.google.devtools.ksp")
}

android {
    namespace = "com.mqvpn.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.mqvpn.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 4
        versionName = "0.4.0"
        // arm64-v8a only: must match sdk-native's abiFilters. Adding ABIs here
        // without updating sdk-native produces APKs that crash with
        // UnsatisfiedLinkError on those ABIs (no .so packaged).
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    // Release signing config reads from env vars set by CI. When unset
    // (local `assembleRelease` without env), Gradle leaves the variant
    // unsigned and the build produces an unsigned APK that zipalign can
    // sign later — fine for local inspection.
    val ksPath = System.getenv("MQVPN_KEYSTORE_PATH")
    val ksPass = System.getenv("MQVPN_KEYSTORE_PASSWORD")
    val keyAlias = System.getenv("MQVPN_KEY_ALIAS")
    val keyPass = System.getenv("MQVPN_KEY_PASSWORD")
    val haveSigning = !ksPath.isNullOrBlank() && !ksPass.isNullOrBlank() &&
        !keyAlias.isNullOrBlank() && !keyPass.isNullOrBlank()
    if (haveSigning) {
        signingConfigs {
            create("release") {
                storeFile = file(ksPath!!)
                storePassword = ksPass
                this.keyAlias = keyAlias
                keyPassword = keyPass
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (haveSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    buildFeatures {
        compose = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
}

dependencies {
    implementation(project(":sdk-core"))

    // Compose
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")

    // Hilt
    implementation("com.google.dagger:hilt-android:2.51.1")
    ksp("com.google.dagger:hilt-android-compiler:2.51.1")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")

    // Test
    testImplementation("junit:junit:4.13.2")
    testImplementation("io.mockk:mockk:1.13.13")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}
