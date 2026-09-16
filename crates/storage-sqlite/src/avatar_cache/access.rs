//! Native-facing opaque locators and local metadata. No network work.
use super::*;
pub(super) const AVATAR_TARGET_LOOKUP_SQL: &str = "SELECT group_id_hex FROM chat_list_rows CROSS JOIN chat_presentation_meta m WHERE presentation_row_epoch = ?1 AND m.id = 1 AND m.store_epoch = ?2";
use crate::{ChatPresentationVersion, SelectedAvatar};

/// Stable request locator for one selected source and conversation incarnation.
/// It contains no URL or image key material and is not an authorization grant.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AvatarAssetTarget {
    epoch: Vec<u8>,
    row: Vec<u8>,
    member: Option<String>,
    source: String,
}
impl fmt::Debug for AvatarAssetTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AvatarAssetTarget(..)")
    }
}
impl AvatarAssetTarget {
    pub fn to_opaque(&self) -> String {
        format!(
            "1:{}:{}:{}:{}",
            hex::encode(&self.epoch),
            hex::encode(&self.row),
            self.member.as_deref().unwrap_or(""),
            hex::encode(&self.source)
        )
    }
    pub fn from_opaque(value: &str) -> StorageResult<Self> {
        if value.len() > 1200 {
            return Err(invalid("invalid avatar target"));
        }
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 5 || parts[0] != "1" {
            return Err(invalid("invalid avatar target"));
        }
        let epoch = decode_token(parts[1])?;
        let row = decode_token(parts[2])?;
        let member = if parts[3].is_empty() {
            None
        } else {
            if parts[3].len() != 64 || !parts[3].bytes().all(|v| v.is_ascii_hexdigit()) {
                return Err(invalid("invalid avatar target"));
            }
            Some(parts[3].to_ascii_lowercase())
        };
        let source =
            String::from_utf8(hex::decode(parts[4]).map_err(|_| invalid("invalid avatar target"))?)
                .map_err(|_| invalid("invalid avatar target"))?;
        validate_key(&source)?;
        Ok(Self {
            epoch,
            row,
            member,
            source,
        })
    }
    pub fn member(&self) -> Option<&str> {
        self.member.as_deref()
    }
    pub fn matches_source(&self, selected: &SelectedAvatar) -> bool {
        source_key(selected) == Some(self.source.as_str())
    }
}
impl AvatarAssetRef {
    pub fn to_opaque(&self) -> String {
        format!(
            "{}:{}",
            hex::encode(&self.store_epoch),
            hex::encode(&self.token)
        )
    }
    pub fn from_opaque(value: &str) -> StorageResult<Self> {
        if value.len() != 65 {
            return Err(invalid("invalid avatar reference"));
        }
        let (epoch, token) = value
            .split_once(':')
            .ok_or_else(|| invalid("invalid avatar reference"))?;
        Ok(Self {
            store_epoch: decode_token(epoch)?,
            token: decode_token(token)?,
        })
    }
}
fn decode_token(value: &str) -> StorageResult<Vec<u8>> {
    if value.len() != 32 {
        return Err(invalid("invalid avatar token"));
    }
    hex::decode(value).map_err(|_| invalid("invalid avatar token"))
}
pub(crate) fn source_key(selected: &SelectedAvatar) -> Option<&str> {
    match selected {
        SelectedAvatar::RemoteImage { cache_key, .. }
        | SelectedAvatar::EncryptedGroupImage { cache_key, .. } => Some(cache_key),
        SelectedAvatar::Placeholder { .. } => None,
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AvatarAssetPresentation {
    pub target: AvatarAssetTarget,
    pub reference: Option<AvatarAssetRef>,
    pub status: AvatarAssetStatus,
    pub acquisition: Option<AvatarAcquisitionState>,
}
impl AvatarAssetPresentation {
    pub fn invalidated(target: AvatarAssetTarget) -> Self {
        Self {
            target,
            reference: None,
            status: AvatarAssetStatus {
                availability: AvatarAvailability::Invalidated,
                content_revision: 0,
                byte_count: 0,
            },
            acquisition: None,
        }
    }
}
impl SqliteAccountStorage {
    pub fn avatar_target_presentation(
        &self,
        group: &str,
        member: Option<&str>,
        selected: &SelectedAvatar,
        now: u64,
    ) -> StorageResult<Option<AvatarAssetPresentation>> {
        target_presentation(&*self.lock()?, group, member, selected, now)
    }
    /// Read one conversation's header/identity metadata under one account lock.
    pub fn avatar_target_presentations(
        &self,
        group: &str,
        selections: &[(Option<&str>, &SelectedAvatar)],
        now: u64,
    ) -> StorageResult<Vec<Option<AvatarAssetPresentation>>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let result = selections
            .iter()
            .map(|(member, selected)| target_presentation(&tx, group, *member, selected, now))
            .collect::<StorageResult<Vec<_>>>()?;
        tx.commit().storage()?;
        Ok(result)
    }
    /// Resolve only within this account and the same retained chat incarnation.
    pub fn resolve_avatar_target(
        &self,
        target: &AvatarAssetTarget,
    ) -> StorageResult<Option<String>> {
        self.lock()?
            .query_row(
                AVATAR_TARGET_LOOKUP_SQL,
                params![target.row, target.epoch],
                |r| r.get(0),
            )
            .optional()
            .storage()
    }
    /// Revalidate the target under the same transaction as demand registration.
    pub fn request_avatar_target(
        &self,
        target: &AvatarAssetTarget,
        selected: &SelectedAvatar,
        version: Option<&ChatPresentationVersion>,
        now: u64,
    ) -> StorageResult<AvatarAssetPresentation> {
        self.connection.with_transaction(|| {
            let Some(group) = self.resolve_avatar_target(target)? else {
                return Ok(AvatarAssetPresentation::invalidated(target.clone()));
            };
            if !target.matches_source(selected) {
                return Ok(AvatarAssetPresentation::invalidated(target.clone()));
            }
            if let Some(member) = target.member() {
                let version = version.ok_or_else(|| invalid("avatar profile version missing"))?;
                // A version mismatch durably registers demand while directory
                // adoption catches up. The target remains current and Missing.
                self.request_identity_avatar_acquisition(&group, member, selected, version)?;
            } else {
                let crate::ChatPresentationRead::Ready(current) = self.chat_presentation(&group)?
                else {
                    return Ok(AvatarAssetPresentation::invalidated(target.clone()));
                };
                if current.presentation.avatar != *selected {
                    return Ok(AvatarAssetPresentation::invalidated(target.clone()));
                }
                self.request_avatar_acquisition(
                    &format!("chat:{}", hex::encode(&target.row)),
                    selected,
                    true,
                )?;
            }
            Ok(self
                .avatar_target_presentation(&group, target.member(), selected, now)?
                .unwrap_or_else(|| AvatarAssetPresentation::invalidated(target.clone())))
        })
    }
}
pub(crate) fn target_presentation(
    conn: &Connection,
    group: &str,
    member: Option<&str>,
    selected: &SelectedAvatar,
    now: u64,
) -> StorageResult<Option<AvatarAssetPresentation>> {
    let Some(source) = source_key(selected) else {
        return Ok(None);
    };
    conn.prepare_cached(
        "SELECT m.store_epoch, r.presentation_row_epoch, a.token,
                coalesce(a.content_revision, 0), coalesce(length(a.bytes), 0),
                a.refresh_at, q.state
         FROM chat_list_rows r CROSS JOIN chat_presentation_meta m
         LEFT JOIN avatar_assets a ON a.owner_key =
             CASE WHEN ?2 IS NULL THEN 'chat:' || lower(hex(r.presentation_row_epoch))
             ELSE 'identity:chat:' || lower(hex(r.presentation_row_epoch)) || ':' || ?2 END
             AND a.source_key = ?3
         LEFT JOIN avatar_acquisition q ON q.token = a.token
         WHERE r.group_id_hex = ?1 AND m.id = 1",
    )
    .storage()?
    .query_row(params![group, member, source], |r| {
        let epoch: Vec<u8> = r.get(0)?;
        let row: Vec<u8> = r.get(1)?;
        let token: Option<Vec<u8>> = r.get(2)?;
        let status = status_columns(r, 3, now)?;
        let acquisition: Option<i64> = r.get(6)?;
        Ok(AvatarAssetPresentation {
            target: AvatarAssetTarget {
                epoch: epoch.clone(),
                row,
                member: member.map(str::to_owned),
                source: source.to_owned(),
            },
            reference: token.map(|token| AvatarAssetRef {
                store_epoch: epoch,
                token,
            }),
            status,
            acquisition: acquisition.map(|state| match state {
                0 => AvatarAcquisitionState::Idle,
                1 => AvatarAcquisitionState::Queued,
                2 => AvatarAcquisitionState::Fetching,
                3 => AvatarAcquisitionState::RetryScheduled,
                _ => AvatarAcquisitionState::Blocked,
            }),
        })
    })
    .optional()
    .storage()
}
