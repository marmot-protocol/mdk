//! Read-only retained-asset discovery. Looking up bytes never registers demand.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedAttachmentAsset {
    pub reference: AttachmentAssetRef,
    pub byte_count: u64,
}

impl SqliteAccountStorage {
    /// Metadata only for the exact original source slot. None means no currently
    /// readable retained asset; it does not imply that a download was requested.
    pub fn retained_attachment_asset(
        &self,
        group: &str,
        message: &str,
        source: &str,
        index: u32,
        now: u64,
    ) -> StorageResult<Option<RetainedAttachmentAsset>> {
        let conn = self.lock()?;
        conn.query_row(
            &format!(
                "SELECT q.token,length(b.bytes) FROM attachment_acquisition q
                 JOIN retained_attachment_bytes b USING(token)
                 WHERE q.group_id_hex=?1 AND q.message_id_hex=?2
                   AND q.source_message_id_hex=?3 AND q.attachment_index=?4
                   AND q.state=3 AND {SOURCE_MATCH}
                   AND (q.expires_at IS NULL OR q.expires_at>?5)"
            ),
            params![group, message, source, index, u64_to_i64(now)?],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, nonnegative(r, 1)?)),
        )
        .optional()
        .storage()?
        .map(|(token, byte_count)| {
            Ok(RetainedAttachmentAsset {
                reference: AttachmentAssetRef {
                    store_epoch: epoch(&conn)?,
                    token,
                },
                byte_count,
            })
        })
        .transpose()
    }
}

impl AttachmentAssetRef {
    /// Opaque locator, not an authorization grant. Contains no URL/key material.
    pub fn to_opaque(&self) -> String {
        format!(
            "1:{}:{}",
            hex::encode(&self.store_epoch),
            hex::encode(&self.token)
        )
    }
    pub fn from_opaque(value: &str) -> StorageResult<Self> {
        if value.len() != 67 {
            return Err(invalid("invalid attachment asset reference"));
        }
        let mut parts = value.split(':');
        if parts.next() != Some("1") {
            return Err(invalid("invalid attachment asset reference"));
        }
        let decode = |part: Option<&str>| {
            let part = part
                .filter(|v| v.len() == 32)
                .ok_or_else(|| invalid("invalid attachment asset reference"))?;
            hex::decode(part).map_err(|_| invalid("invalid attachment asset reference"))
        };
        let store_epoch = decode(parts.next())?;
        let token = decode(parts.next())?;
        if parts.next().is_some() {
            return Err(invalid("invalid attachment asset reference"));
        }
        Ok(Self { store_epoch, token })
    }
}
