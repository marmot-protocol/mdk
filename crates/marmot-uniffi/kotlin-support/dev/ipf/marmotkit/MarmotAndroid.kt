package dev.ipf.marmotkit

import android.content.Context
import io.crates.keyring.Keyring

/**
 * Android initialization bridge for MarmotKit.
 *
 * The `Marmot(...)` constructor builds the Android-native keyring store, which
 * talks to the Android Keystore over JNI and requires the `ndk-context` to be
 * initialized with the application [Context] first. Android consumers MUST call
 * [initialize] from `Application.onCreate` (or otherwise before the first
 * `Marmot(...)` constructor), otherwise construction crashes with
 * `android context was not initialized`.
 *
 * Usage:
 * ```kotlin
 * class MarmotApplication : Application() {
 *     override fun onCreate() {
 *         super.onCreate()
 *         MarmotAndroid.initialize(this)
 *         // ... Marmot(rootPath, relayUrls) is now safe to construct
 *     }
 * }
 * ```
 *
 * Safe to call once per process. If the host framework (e.g. Tauri Mobile,
 * Dioxus Mobile, or `android-activity`) already initialized `ndk-context`, do
 * not call this again — initialize the context exactly once.
 */
object MarmotAndroid {
    @JvmStatic
    fun initialize(context: Context) {
        Keyring.initializeNdkContext(context.applicationContext)
    }
}
