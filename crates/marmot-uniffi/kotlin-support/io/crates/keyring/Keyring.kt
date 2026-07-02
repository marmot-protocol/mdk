package io.crates.keyring

import android.content.Context

/**
 * JNI shim required by the `android-native-keyring-store` crate.
 *
 * That crate is statically linked into `libmarmot_uniffi.so`, so its
 * `Java_io_crates_keyring_Keyring_00024Companion_initializeNdkContext` symbol is
 * exported from that single library rather than from a standalone keyring `.so`.
 * The package, class name, and the `companion object` + `external fun` shape are
 * fixed by the crate's JNI contract and MUST NOT change — only the loaded
 * library name is darkmatter-specific.
 *
 * Do not call this directly from app code; use
 * [dev.ipf.marmotkit.MarmotAndroid.initialize] instead.
 */
class Keyring {
    companion object {
        init {
            System.loadLibrary("marmot_uniffi")
        }

        external fun initializeNdkContext(context: Context)
    }
}
