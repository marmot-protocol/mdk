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
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
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
fn from_extensions(
    extensions: &Extensions<GroupContext>,
) -> Result<Option<MarmotMultiDevice>, Error> {
    for ext in extensions.iter() {
        if let Extension::Unknown(ext_type, data) = ext
            && *ext_type == MULTI_DEVICE_EXTENSION_TYPE
        {
            let (parsed, _) = MarmotMultiDevice::tls_deserialize_bytes(data.0.as_slice())
                .map_err(|e| Error::ExtensionFormatError(e.to_string()))?;
            parsed.validate()?;
            return Ok(Some(parsed));
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
/// 3. All members advertise `0xF2F0` in their leaf-node capabilities
///
/// Condition 3 is inferred, not verified per-leaf: when `required_capabilities`
/// mandates `0xF2F0`, OpenMLS enforces that every leaf advertises it at commit
/// time, so conditions 1+2 imply condition 3 for groups in a valid MLS state.
/// If the group was deserialized from a partial write (e.g., crash recovery),
/// this inference may not hold. A `debug_assert!` on the own leaf is included
/// to catch violations in development; a full per-leaf check is not possible
/// through OpenMLS's public `members()` API.
pub fn is_multi_device_enabled(group: &MlsGroup) -> bool {
    // 1. Extension present and valid
    let ext_present = matches!(MarmotMultiDevice::from_group(group), Ok(Some(_)));

    // 2. required_capabilities includes 0xF2F0
    let required = is_required_in_capabilities(group.extensions());

    // 3. At least one member (implied by conditions 1+2 + MLS required_capabilities enforcement)
    let has_members = group.members().next().is_some();

    let enabled = ext_present && required && has_members;

    // Spot-check: verify our own leaf advertises 0xF2F0 when the gate is enabled.
    // This catches corruption visible to the local node; per-member checks would
    // require internal tree access not exposed by OpenMLS.
    if enabled {
        debug_assert!(
            group.own_leaf().is_some_and(|leaf| {
                leaf.capabilities()
                    .extensions()
                    .contains(&ExtensionType::Unknown(MULTI_DEVICE_EXTENSION_TYPE))
            }),
            "MIP-06 gate is enabled but own leaf does not advertise 0xF2F0 — \
             possible corrupt group state from partial write"
        );
    }

    enabled
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

    #[test]
    fn test_default_creates_current_version() {
        let ext = MarmotMultiDevice::default();
        assert_eq!(ext.version(), MarmotMultiDevice::CURRENT_VERSION);
        assert!(ext.validate().is_ok());
    }

    #[test]
    fn test_version_u16_max_rejected() {
        let ext = MarmotMultiDevice { version: u16::MAX };
        assert!(matches!(
            ext.validate(),
            Err(crate::error::Error::InvalidExtensionVersion(v)) if v == u16::MAX
        ));
    }

    #[test]
    fn test_version_2_rejected() {
        let ext = MarmotMultiDevice { version: 2 };
        assert!(matches!(
            ext.validate(),
            Err(crate::error::Error::InvalidExtensionVersion(2))
        ));
    }

    #[test]
    fn test_as_extension_roundtrip_through_from_extensions() {
        use openmls::prelude::GroupContext;

        // Build the extension
        let ext = MarmotMultiDevice::new();
        let openmls_ext = ext.as_extension().unwrap();

        // Put it in an Extensions set and extract it back
        let extensions: Extensions<GroupContext> =
            Extensions::single(openmls_ext).expect("should build extensions");
        let extracted = from_extensions(&extensions).unwrap();
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap(), ext);
    }

    #[test]
    fn test_from_extensions_returns_none_when_absent() {
        use openmls::prelude::GroupContext;

        let extensions: Extensions<GroupContext> = Extensions::empty();
        let result = from_extensions(&extensions).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_from_extensions_rejects_invalid_version() {
        use openmls::prelude::GroupContext;
        use tls_codec::Serialize;

        // Manually construct an extension with version 0
        let bad_ext = MarmotMultiDevice { version: 0 };
        let mut bytes = Vec::new();
        bad_ext.tls_serialize(&mut bytes).unwrap();

        let openmls_ext = Extension::Unknown(
            MULTI_DEVICE_EXTENSION_TYPE,
            openmls::extensions::UnknownExtension(bytes),
        );
        let extensions: Extensions<GroupContext> =
            Extensions::single(openmls_ext).expect("should build extensions");

        let result = from_extensions(&extensions);
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_serialization_size() {
        use tls_codec::Serialize;

        let ext = MarmotMultiDevice::new();
        let mut bytes = Vec::new();
        ext.tls_serialize(&mut bytes).unwrap();
        // version is a u16 = 2 bytes
        assert_eq!(bytes.len(), 2);
    }
}
