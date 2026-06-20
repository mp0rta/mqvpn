plugins {
    id("com.android.application") version "9.2.1" apply false
    id("com.android.library") version "9.2.1" apply false
    // Kotlin 2.4.x is blocked on Hilt: dagger 2.59.2 bundles kotlin-metadata-jvm
    // that reads metadata <= 2.3.0, so :app:hiltJavaCompileDebug fails on 2.4.0
    // output. Bump together with a Hilt release that supports Kotlin 2.4.
    id("org.jetbrains.kotlin.plugin.serialization") version "2.4.0" apply false
    id("org.jetbrains.kotlin.plugin.parcelize") version "2.4.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.0" apply false
    id("com.google.dagger.hilt.android") version "2.59.2" apply false
    id("com.google.devtools.ksp") version "2.3.9" apply false
}
