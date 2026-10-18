//! The deployment record a C host passes at construction, as an opaque
//! handle: start from a preset, change what differs, then pass it to
//! `marmot_client_new_with_deployment`. Mirrors UniFFI's `MarmotDeploymentFfi`.

use std::ffi::c_char;

use marmot_uniffi::{MarmotDeploymentFfi, OpenRankingProviderFfi};

use crate::memory::{CFree, boxed, free_boxed, free_guard, optional_str, required_str, str_array};
use crate::{MarmotStatus, ffi_guard, preflight_out_ptr};

/// One deployment's services and identifiers. Create it with
/// `marmot_deployment_white_noise` or `marmot_deployment_neutral` and free it
/// with `marmot_deployment_free`. Blank values count as unset.
pub struct MarmotDeployment {
    pub(crate) inner: MarmotDeploymentFfi,
}
impl CFree for MarmotDeployment {
    unsafe fn free_in_place(&mut self) {}
}

unsafe fn write_deployment(
    out: *mut *mut MarmotDeployment,
    inner: MarmotDeploymentFfi,
) -> MarmotStatus {
    if let Err(status) = unsafe { preflight_out_ptr(out) } {
        return status;
    }
    unsafe { out.write(boxed(MarmotDeployment { inner })) };
    MarmotStatus::Ok
}

unsafe fn edit(
    deployment: *mut MarmotDeployment,
    change: impl FnOnce(&mut MarmotDeploymentFfi) -> Result<(), MarmotStatus>,
) -> MarmotStatus {
    ffi_guard(|| {
        let Some(deployment) = (unsafe { deployment.as_mut() }) else {
            crate::status::set_last_error("deployment argument was NULL");
            return MarmotStatus::NullPointer;
        };
        match change(&mut deployment.inner) {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => status,
        }
    })
}

/// White Noise's deployment as this build compiled it, the values every
/// constructor uses without a deployment until the neutral default lands.
/// Free with marmot_deployment_free.
/// # Safety
/// out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_white_noise(
    out: *mut *mut MarmotDeployment,
) -> MarmotStatus {
    ffi_guard(|| unsafe { write_deployment(out, marmot_uniffi::marmot_deployment_white_noise()) })
}

/// No deployment services: every list empty, every option unset, and the
/// neutral keychain service org.marmot-protocol.mdk. Free with
/// marmot_deployment_free.
/// # Safety
/// out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_neutral(
    out: *mut *mut MarmotDeployment,
) -> MarmotStatus {
    ffi_guard(|| unsafe { write_deployment(out, marmot_uniffi::marmot_deployment_neutral()) })
}

/// Free a deployment; NULL is accepted. A client constructed with it keeps
/// its own copy.
/// # Safety
/// deployment must be NULL or live, with no call on it in progress.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_free(deployment: *mut MarmotDeployment) {
    free_guard(|| unsafe { free_boxed(deployment) });
}

/// Replace the relays this deployment operates, which certify recovery.
/// # Safety
/// deployment must be live; relays must point to relays_len valid strings (or be NULL with 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_set_recovery_operated_relays(
    deployment: *mut MarmotDeployment,
    relays: *const *const c_char,
    relays_len: usize,
) -> MarmotStatus {
    unsafe {
        edit(deployment, |inner| {
            inner.recovery_operated_relays = str_array(relays, relays_len)?;
            Ok(())
        })
    }
}

/// Replace the public indexers onboarding and account setup also search.
/// # Safety
/// deployment must be live; relays must point to relays_len valid strings (or be NULL with 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_set_discovery_indexer_relays(
    deployment: *mut MarmotDeployment,
    relays: *const *const c_char,
    relays_len: usize,
) -> MarmotStatus {
    unsafe {
        edit(deployment, |inner| {
            inner.discovery_indexer_relays = str_array(relays, relays_len)?;
            Ok(())
        })
    }
}

/// Replace the Blossom servers signed into a new group's encrypted-media component.
/// # Safety
/// deployment must be live; endpoints must point to endpoints_len valid strings (or be NULL with 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_set_new_group_media_endpoints(
    deployment: *mut MarmotDeployment,
    endpoints: *const *const c_char,
    endpoints_len: usize,
) -> MarmotStatus {
    unsafe {
        edit(deployment, |inner| {
            inner.new_group_media_endpoints = str_array(endpoints, endpoints_len)?;
            Ok(())
        })
    }
}

/// Set the encrypted group-image server; NULL unsets it.
/// # Safety
/// deployment must be live; endpoint must be NULL or a valid string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_set_group_image_endpoint(
    deployment: *mut MarmotDeployment,
    endpoint: *const c_char,
) -> MarmotStatus {
    unsafe {
        edit(deployment, |inner| {
            inner.group_image_endpoint = optional_str(endpoint)?;
            Ok(())
        })
    }
}

/// Set the public profile-image upload server; NULL unsets it.
/// # Safety
/// deployment must be live; endpoint must be NULL or a valid string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_set_profile_image_endpoint(
    deployment: *mut MarmotDeployment,
    endpoint: *const c_char,
) -> MarmotStatus {
    unsafe {
        edit(deployment, |inner| {
            inner.profile_image_endpoint = optional_str(endpoint)?;
            Ok(())
        })
    }
}

/// Set the Open Ranking search endpoint and its profile relays; a NULL
/// endpoint, or no profile relay, turns the tier off.
/// # Safety
/// deployment must be live; search_endpoint must be NULL or a valid string;
/// profile_relays must point to profile_relays_len valid strings (or be NULL with 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_set_open_ranking(
    deployment: *mut MarmotDeployment,
    search_endpoint: *const c_char,
    profile_relays: *const *const c_char,
    profile_relays_len: usize,
) -> MarmotStatus {
    unsafe {
        edit(deployment, |inner| {
            let profile_relays = str_array(profile_relays, profile_relays_len)?;
            inner.open_ranking =
                optional_str(search_endpoint)?.map(|search_endpoint| OpenRankingProviderFfi {
                    search_endpoint,
                    profile_relays,
                });
            Ok(())
        })
    }
}

/// Replace the KeyPackage `client` tags ranked first and ranked last.
/// # Safety
/// deployment must be live; each list must point to its length of valid strings (or be NULL with 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_set_key_package_client_preference(
    deployment: *mut MarmotDeployment,
    preferred: *const *const c_char,
    preferred_len: usize,
    last: *const *const c_char,
    last_len: usize,
) -> MarmotStatus {
    unsafe {
        edit(deployment, |inner| {
            // Read both lists before changing either, so a failure leaves the
            // handle as it was.
            let preferred = str_array(preferred, preferred_len)?;
            let last = str_array(last, last_len)?;
            inner.key_package_preferred_clients = preferred;
            inner.key_package_last_clients = last;
            Ok(())
        })
    }
}

/// Set the NIP-32 namespace on moderation report labels; NULL unsets it, and
/// reporting then refuses a destination.
/// # Safety
/// deployment must be live; namespace must be NULL or a valid string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_set_moderation_label_namespace(
    deployment: *mut MarmotDeployment,
    namespace: *const c_char,
) -> MarmotStatus {
    unsafe {
        edit(deployment, |inner| {
            inner.moderation_label_namespace = optional_str(namespace)?;
            Ok(())
        })
    }
}

/// Set the platform keychain service for account secrets when no secret
/// store is supplied. Changing it for an existing install strands the secrets
/// stored under the old name.
/// # Safety
/// deployment must be live; name must be a valid string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_deployment_set_keychain_service(
    deployment: *mut MarmotDeployment,
    name: *const c_char,
) -> MarmotStatus {
    unsafe {
        edit(deployment, |inner| {
            inner.keychain_service = required_str(name)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    fn white_noise() -> *mut MarmotDeployment {
        let mut out = std::ptr::null_mut();
        assert_eq!(
            unsafe { marmot_deployment_white_noise(&mut out) },
            MarmotStatus::Ok
        );
        out
    }

    #[test]
    fn presets_match_the_uniffi_records() {
        // Handles count against the process-wide allocation audit.
        let _guard = crate::memory::audit::test_lock();
        let deployment = white_noise();
        assert_eq!(
            unsafe { &(*deployment).inner },
            &marmot_uniffi::marmot_deployment_white_noise()
        );
        unsafe { marmot_deployment_free(deployment) };
        let mut neutral = std::ptr::null_mut();
        assert_eq!(
            unsafe { marmot_deployment_neutral(&mut neutral) },
            MarmotStatus::Ok
        );
        assert_eq!(
            unsafe { &(*neutral).inner },
            &marmot_uniffi::marmot_deployment_neutral()
        );
        unsafe { marmot_deployment_free(neutral) };
    }

    #[test]
    fn setters_replace_each_field() {
        // Handles count against the process-wide allocation audit.
        let _guard = crate::memory::audit::test_lock();
        let deployment = white_noise();
        let relay = CString::new("wss://relay.example").unwrap();
        let relays = [relay.as_ptr()];
        let server = CString::new("https://blossom.example").unwrap();
        let namespace = CString::new("org.example.report").unwrap();
        let keychain = CString::new("org.example.app").unwrap();
        unsafe {
            assert_eq!(
                marmot_deployment_set_recovery_operated_relays(deployment, relays.as_ptr(), 1),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_deployment_set_discovery_indexer_relays(deployment, std::ptr::null(), 0),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_deployment_set_new_group_media_endpoints(deployment, std::ptr::null(), 0),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_deployment_set_group_image_endpoint(deployment, server.as_ptr()),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_deployment_set_profile_image_endpoint(deployment, std::ptr::null()),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_deployment_set_open_ranking(
                    deployment,
                    std::ptr::null(),
                    relays.as_ptr(),
                    1
                ),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_deployment_set_key_package_client_preference(
                    deployment,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0
                ),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_deployment_set_moderation_label_namespace(deployment, namespace.as_ptr()),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_deployment_set_keychain_service(deployment, keychain.as_ptr()),
                MarmotStatus::Ok
            );
            let inner = &(*deployment).inner;
            assert_eq!(inner.recovery_operated_relays, ["wss://relay.example"]);
            assert!(inner.discovery_indexer_relays.is_empty());
            assert!(inner.new_group_media_endpoints.is_empty());
            assert_eq!(
                inner.group_image_endpoint.as_deref(),
                Some("https://blossom.example")
            );
            assert_eq!(inner.profile_image_endpoint, None);
            assert_eq!(inner.open_ranking, None);
            assert!(inner.key_package_preferred_clients.is_empty());
            assert_eq!(
                inner.moderation_label_namespace.as_deref(),
                Some("org.example.report")
            );
            assert_eq!(inner.keychain_service, "org.example.app");
            marmot_deployment_free(deployment);
        }
    }

    #[test]
    fn null_arguments_are_rejected() {
        // Handles count against the process-wide allocation audit.
        let _guard = crate::memory::audit::test_lock();
        let relay = CString::new("wss://relay.example").unwrap();
        unsafe {
            assert_eq!(
                marmot_deployment_set_keychain_service(std::ptr::null_mut(), relay.as_ptr()),
                MarmotStatus::NullPointer
            );
            let deployment = white_noise();
            assert_eq!(
                marmot_deployment_set_keychain_service(deployment, std::ptr::null()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_deployment_set_recovery_operated_relays(deployment, std::ptr::null(), 1),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_deployment_white_noise(std::ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            marmot_deployment_free(deployment);
            marmot_deployment_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn a_failed_preference_setter_leaves_both_lists_unchanged() {
        // Handles count against the process-wide allocation audit.
        let _guard = crate::memory::audit::test_lock();
        let deployment = white_noise();
        let preferred = CString::new("other").unwrap();
        let preferred = [preferred.as_ptr()];
        let invalid = [0xff_u8, 0];
        let last = [invalid.as_ptr().cast::<c_char>()];
        unsafe {
            assert_eq!(
                marmot_deployment_set_key_package_client_preference(
                    deployment,
                    preferred.as_ptr(),
                    1,
                    last.as_ptr(),
                    1
                ),
                MarmotStatus::InvalidUtf8
            );
            let inner = &(*deployment).inner;
            assert_eq!(inner.key_package_preferred_clients, ["whitenoise"]);
            assert_eq!(inner.key_package_last_clients, ["amethyst"]);
            marmot_deployment_free(deployment);
        }
    }
}
