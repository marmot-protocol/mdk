//! MIP-06 `marmot_multi_device` extension (`0xF2F0`).
//!
//! Defines the signaling extension and the three-part gate that guards
//! multi-device External Commit behavior.

use openmls::extensions::{Extension, ExtensionType, Extensions};
use openmls::group::MlsGroup;
use openmls::prelude::GroupContext;
use tls_codec::{DeserializeBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::constant::MULTI_DEVICE_EXTENSION_TYPE;
use crate::error::Error;

/// TLS-serializable MIP-06 multi-device extension.
///
/// ```tls
/// struct {
///     uint16 version;  // current: 1
/// } MarmotMultiDevice;
/// ```
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct MarmotMultiDevice {
    version: u16,
}

impl MarmotMultiDevice {
    /// Current version of the MIP-06 extension.
    pub const CURRENT_VERSION: u16 = 1;

    /// Create a new `MarmotMultiDevice` extension at the current version.
    pub fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
        }
    }

    /// Get the version field.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Validate version rules per MIP-06.
    pub fn validate(&self) -> Result<(), Error> {
        match self.version {
            0 => Err(Error::InvalidExtensionVersion(0)),
            1 => Ok(()),
            v => Err(Error::InvalidExtensionVersion(v)),
        }
    }

    /// Build an OpenMLS `Extension` wrapping this struct.
    pub fn as_extension(&self) -> Result<Extension, Error> {
        use tls_codec::Serialize;
        let mut bytes = Vec::new();
        self.tls_serialize(&mut bytes)
            .map_err(|e| Error::ExtensionFormatError(e.to_string()))?;
        Ok(Extension::Unknown(
            MULTI_DEVICE_EXTENSION_TYPE,
            openmls::extensions::UnknownExtension(bytes),
        ))
    }

    /// Extract from a GroupContext's extensions, returning `None` if absent.
    pub fn from_group_context(context: &GroupContext) -> Result<Option<Self>, Error> {
        from_extensions(context.extensions())
    }

    /// Extract from an `MlsGroup`, returning `None` if absent.
    pub fn from_group(group: &MlsGroup) -> Result<Option<Self>, Error> {
        from_extensions(group.extensions())
    }
}

impl Default for MarmotMultiDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract and validate a `MarmotMultiDevice` from an `Extensions` set.
fn from_extensions(extensions: &Extensions<GroupContext>) -> Result<Option<MarmotMultiDevice>, Error> {
    for ext in extensions.iter() {
        if let Extension::Unknown(ext_type, data) = ext {
            if *ext_type == MULTI_DEVICE_EXTENSION_TYPE {
                let (parsed, _) =
                    MarmotMultiDevice::tls_deserialize_bytes(data.0.as_slice())
                        .map_err(|e| Error::ExtensionFormatError(e.to_string()))?;
                parsed.validate()?;
                return Ok(Some(parsed));
            }
        }
    }
    Ok(None)
}

// ── Signaling gate ──────────────────────────────────────────────────────

/// Check whether the full MIP-06 signaling gate is satisfied for a group.
///
/// The gate requires all three of:
/// 1. `GroupContext.extensions` contains a valid `marmot_multi_device` (`0xF2F0`)
/// 2. `required_capabilities` requires `0xF2F0`
/// 3. At least one existing member advertises `0xF2F0` in capabilities
///
/// For condition 3: when `required_capabilities` mandates `0xF2F0`, MLS validation
/// ensures all members must advertise it. Conditions 1+2 therefore imply condition 3
/// for groups in a valid state that have at least one member.
pub fn is_multi_device_enabled(group: &MlsGroup) -> bool {
    // 1. Extension present and valid
    let ext_present = matches!(MarmotMultiDevice::from_group(group), Ok(Some(_)));

    // 2. required_capabilities includes 0xF2F0
    let required = is_required_in_capabilities(group.extensions());

    // 3. At least one member (implied by conditions 1+2 + MLS required_capabilities enforcement)
    let has_members = group.members().next().is_some();

    ext_present && required && has_members
}

/// Check if `required_capabilities` includes `0xF2F0`.
fn is_required_in_capabilities(extensions: &Extensions<GroupContext>) -> bool {
    for ext in extensions.iter() {
        if let Extension::RequiredCapabilities(req_caps) = ext {
            return req_caps
                .extension_types()
                .contains(&ExtensionType::Unknown(MULTI_DEVICE_EXTENSION_TYPE));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marmot_multi_device_roundtrip() {
        use tls_codec::Serialize;

        let ext = MarmotMultiDevice::new();
        assert_eq!(ext.version(), 1);

        let mut bytes = Vec::new();
        ext.tls_serialize(&mut bytes).unwrap();
        let (decoded, _) = MarmotMultiDevice::tls_deserialize_bytes(&bytes).unwrap();
        assert_eq!(decoded, ext);
    }

    #[test]
    fn test_version_validation() {
        let v1 = MarmotMultiDevice { version: 1 };
        assert!(v1.validate().is_ok());

        let v0 = MarmotMultiDevice { version: 0 };
        assert!(matches!(
            v0.validate(),
            Err(Error::InvalidExtensionVersion(0))
        ));

        let v99 = MarmotMultiDevice { version: 99 };
        assert!(matches!(
            v99.validate(),
            Err(Error::InvalidExtensionVersion(99))
        ));
    }

    #[test]
    fn test_as_extension() {
        let ext = MarmotMultiDevice::new();
        let openmls_ext = ext.as_extension().unwrap();
        match openmls_ext {
            Extension::Unknown(ext_type, _) => {
                assert_eq!(ext_type, MULTI_DEVICE_EXTENSION_TYPE);
            }
            _ => panic!("Expected Unknown extension"),
        }
    }
}
