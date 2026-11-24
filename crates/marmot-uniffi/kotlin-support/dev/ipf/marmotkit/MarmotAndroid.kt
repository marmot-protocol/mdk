package dev.ipf.marmotkit

import android.content.Context
import io.crates.keyring.Keyring

/**
 * Android initialization bridge for MarmotKit.
 *
 * Account ownership uses the application identity and storage container, including
 * with file or host-provided secret stores. The native store also uses Android
 * Keystore over JNI. Both require `ndk-context` with the application [Context].
 * Android consumers MUST call
 * [initialize] from `Application.onCreate` (or otherwise before the first
 * `Marmot(...)` constructor), otherwise construction or credential access fails.
 *
 * Usage:
 * ```kotlin
 * class MarmotApplication : Application() {
 *     override fun onCreate() {
 *         super.onCreate()
 *         MarmotAndroid.initialize(this)
 *         // ... Marmot(rootPath, relayUrls, marmotDeploymentWhiteNoise()) is now safe to construct
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
