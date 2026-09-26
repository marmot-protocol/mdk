//! Active opt-in v5 forensic record contract. New app audit sessions record
//! typed lifecycle, app, Welcome and operational events here; historical v4 files remain
//! readable and their whole-file upload contract stays separate.
mod operational;
mod primitives;
mod strict_json;
mod types;
mod validation;
pub use operational::{OperationalEvent, group_ref_from_legacy_hex};
pub use primitives::*;
pub use types::*;

pub const SCHEMA_VERSION: &str = "marmot-forensics-audit/v5";
pub const MAX_BODY_BYTES: usize = 65_535;
pub const MAX_ENDPOINTS: usize = 16;
pub const MAX_MEMBERS: usize = 64;
pub const JSON_SCHEMA: &str = include_str!("../../schema/audit-log-event.v5.schema.json");

/// Safe categorical error: never includes supplied JSON, identifiers or free-form values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractError(&'static str);
impl ContractError {
    pub(crate) fn rule(message: &'static str) -> Self {
        Self(message)
    }
}
impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ContractError {}

/// Validated, immutable record. Keep original input bytes for replay; decoding is not
/// permission to re-serialize existing records into a different original body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record(RecordFields);
impl Record {
    pub fn new(fields: RecordFields) -> Result<Self, ContractError> {
        validation::validate(&fields)?;
        let record = Self(fields);
        record.to_json()?;
        Ok(record)
    }
    pub fn fields(&self) -> &RecordFields {
        &self.0
    }
    /// Decode one JSON body (no trailing JSONL newline). Reject duplicate keys before
    /// tagged-enum buffering, which can otherwise discard duplicate discriminators.
    pub fn from_json(body: &[u8]) -> Result<Self, ContractError> {
        if body.is_empty()
            || body.len() > MAX_BODY_BYTES
            || body.contains(&b'\n')
            || body.contains(&b'\r')
        {
            return Err(ContractError::rule("invalid body framing or size"));
        }
        let value = strict_json::parse(body)?;
        let fields = serde_json::from_value(value.clone())
            .map_err(|_| ContractError::rule("invalid v5 record shape or scalar"))?;
        // Serde accepts enum indexes and object-form unit variants that the
        // wire schema rejects. Compare parsed values, not original JSON text:
        // key order, whitespace and equivalent string escapes remain valid.
        let encoded = serde_json::to_value(&fields)
            .map_err(|_| ContractError::rule("record serialization failed"))?;
        if encoded != value {
            return Err(ContractError::rule("invalid v5 record shape or scalar"));
        }
        Self::new(fields)
    }
    /// Compact UTF-8 JSON body, excluding the JSONL newline.
    pub fn to_json(&self) -> Result<Vec<u8>, ContractError> {
        let body = serde_json::to_vec(&self.0)
            .map_err(|_| ContractError::rule("record serialization failed"))?;
        if body.len() > MAX_BODY_BYTES {
            return Err(ContractError::rule("record exceeds body limit"));
        }
        Ok(body)
    }
}
