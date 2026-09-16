//! Durable, bounded acquisition intent. Network/source policy belongs to marmot-app.
use super::*;
use crate::{ChatPresentationRead, ChatPresentationVersion, SelectedAvatar};

#[derive(serde::Serialize, serde::Deserialize)]
struct DescriptorEnvelope {
    format: u8,
    value: SelectedAvatar,
}

/// Acquisition state is independent of whether stale bytes are still usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AvatarAcquisitionState {
    Idle,
    Queued,
    Fetching,
    RetryScheduled,
    Blocked,
}

/// One claimed attempt. Private fencing fields prevent a superseded worker from
/// completing a newer attempt. The descriptor lives only in protected storage.
pub struct AvatarAcquisition {
    pub reference: AvatarAssetRef,
    pub descriptor: SelectedAvatar,
    revision: u64,
    attempt: Vec<u8>,
}
impl fmt::Debug for AvatarAcquisition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvatarAcquisition").finish_non_exhaustive()
    }
}

impl SqliteAccountStorage {
    /// Persist demand after selecting an authoritative source. Callers must
    /// propagate errors out of any enclosing transaction. Repeated demand joins
    /// existing work and never clears a retry deadline or duplicates a fetch.
    pub fn request_avatar_acquisition(
        &self,
        owner: &str,
        selected: &SelectedAvatar,
        visible: bool,
    ) -> StorageResult<Option<AvatarAssetRef>> {
        validate_key(owner)?;
        let source = match selected {
            SelectedAvatar::RemoteImage { cache_key, .. }
            | SelectedAvatar::EncryptedGroupImage { cache_key, .. } => cache_key,
            SelectedAvatar::Placeholder { .. } => {
                self.lock()?
                    .execute("DELETE FROM avatar_assets WHERE owner_key = ?1", [owner])
                    .storage()?;
                return Ok(None);
            }
        };
        let descriptor = serde_json::to_vec(&DescriptorEnvelope {
            format: 1,
            value: selected.clone(),
        })
        .map_err(|_| invalid("invalid avatar descriptor"))?;
        if descriptor.len() > 16384 {
            return Err(invalid("oversized avatar descriptor"));
        }
        self.connection.with_transaction(|| {
            // Delete changed-source intent before rotating the FK target. This
            // and the replacement binding share the outer transaction.
            self.lock()?.execute(
                "DELETE FROM avatar_acquisition WHERE token IN
                 (SELECT token FROM avatar_assets WHERE owner_key = ?1 AND source_key <> ?2)",
                params![owner, source],
            ).storage()?;
            let reference = self.bind_avatar_source(owner, source)?;
            self.lock()?.execute(
                "INSERT INTO avatar_acquisition(token, descriptor, due, priority) VALUES(?1, ?2, 0, ?3)
                 ON CONFLICT(token) DO UPDATE SET priority = max(priority, excluded.priority)",
                params![reference.token, descriptor, visible],
            ).storage()?;
            Ok(Some(reference))
        })
    }

    /// Metadata-only lookup for the current conversation incarnation. Owner
    /// keys use its fixed-size row epoch, never an artificial MLS group-ID limit.
    pub fn chat_avatar_reference(&self, group: &str) -> StorageResult<Option<AvatarAssetRef>> {
        let conn = self.lock()?;
        let owner = owner_for_chat(&conn, group)?;
        match owner {
            Some(owner) => reference_for_owner(&conn, &owner),
            None => Ok(None),
        }
    }

    fn avatar_chat_owner(&self, group: &str) -> StorageResult<Option<String>> {
        owner_for_chat(&*self.lock()?, group)
    }

    /// Same-source maintenance does not bind or re-demand evicted entries.
    pub(crate) fn maintain_chat_avatar(
        &self,
        group: &str,
        old: Option<&SelectedAvatar>,
        selected: &SelectedAvatar,
    ) -> StorageResult<()> {
        if old != Some(selected) {
            let owner = self
                .avatar_chat_owner(group)?
                .ok_or_else(|| invalid("avatar conversation missing"))?;
            self.request_avatar_acquisition(&owner, selected, false)?;
            // An unchanged presentation cannot consume upgrade work that has
            // not created demand yet. Bootstrap itself always passes old=None.
            self.lock()?
                .execute(
                    "DELETE FROM avatar_acquisition_bootstrap WHERE group_id_hex = ?1",
                    [group],
                )
                .storage()?;
        }
        Ok(())
    }

    /// One bounded upgrade pass. The durable bootstrap ledger is consumed once;
    /// reopening never recreates demand for images subsequently evicted.
    pub fn bootstrap_avatar_acquisition(&self) -> StorageResult<bool> {
        let pending: bool = self
            .lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM avatar_acquisition_bootstrap)",
                [],
                |r| r.get(0),
            )
            .storage()?;
        if !pending {
            return Ok(false);
        }
        self.connection.with_transaction(|| {
            let groups = self.lock()?.prepare(
                "SELECT group_id_hex FROM avatar_acquisition_bootstrap ORDER BY group_id_hex LIMIT 64"
            ).storage()?.query_map([], |r| r.get::<_, String>(0)).storage()?
                .collect::<Result<Vec<_>, _>>().storage()?;
            for group in &groups {
                if let ChatPresentationRead::Ready(value) = self.chat_presentation(group)? {
                    self.maintain_chat_avatar(group, None, &value.presentation.avatar)?;
                } else {
                    // Normal presentation maintenance will create demand when
                    // the pending selection is committed.
                    self.lock()?.execute("DELETE FROM avatar_acquisition_bootstrap WHERE group_id_hex = ?1", [group]).storage()?;
                }
            }
            Ok(groups.len() == 64)
        })
    }

    /// Called once by the exclusive account owner after worker reconstruction.
    /// An interrupted attempt has no published partial bytes and can resume.
    pub fn resume_avatar_acquisition(&self) -> StorageResult<()> {
        self.lock()?
            .execute(
                "UPDATE avatar_acquisition SET state = 1, due = 0, attempt = NULL WHERE state = 2",
                [],
            )
            .storage()?;
        Ok(())
    }

    /// Claim at most one due attempt. Call only after reserving media capacity.
    pub fn claim_avatar_acquisition(&self, now: u64) -> StorageResult<Option<AvatarAcquisition>> {
        let now = u64_to_i64(now)?;
        let due: bool = self
            .lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM avatar_acquisition WHERE due <= ?1)",
                [now],
                |r| r.get(0),
            )
            .storage()?;
        if !due {
            return Ok(None);
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let row = conn.query_row(
                "SELECT a.token, q.descriptor, a.content_revision, m.store_epoch
                 FROM avatar_acquisition q JOIN avatar_assets a USING(token)
                 CROSS JOIN chat_presentation_meta m
                 WHERE q.due <= ?1 AND m.id = 1
                 ORDER BY q.priority DESC, q.due, q.token LIMIT 1",
                [now], |r| Ok((r.get::<_,Vec<u8>>(0)?, r.get::<_,Vec<u8>>(1)?, r.get::<_,i64>(2)?, r.get::<_,Vec<u8>>(3)?)),
            ).optional().storage()?;
            let Some((token, bytes, revision, store_epoch)) = row else { return Ok(None); };
            let descriptor = match serde_json::from_slice::<DescriptorEnvelope>(&bytes) {
                Ok(value) if value.format == 1 => value.value,
                _ => {
                    // A malformed derived job must not starve all later work.
                    conn.execute("UPDATE avatar_acquisition SET state = 4, due = NULL, attempt = NULL WHERE token = ?1", [&token]).storage()?;
                    return Ok(None);
                }
            };
            conn.execute("UPDATE avatar_acquisition SET state = 2, due = ?2, attempt = randomblob(16) WHERE token = ?1", params![token, now.saturating_add(120)]).storage()?;
            let attempt = conn.query_row("SELECT attempt FROM avatar_acquisition WHERE token = ?1", [&token], |r| r.get(0)).storage()?;
            Ok(Some(AvatarAcquisition { reference: AvatarAssetRef { token, store_epoch }, descriptor, revision: u64::try_from(revision).map_err(|_| invalid("invalid avatar revision"))?, attempt }))
        })
    }

    /// Commit complete validated bytes and the next refresh together. A source
    /// change, eviction, restart, or competing publication fences this completion.
    pub fn complete_avatar_acquisition(
        &self,
        job: &AvatarAcquisition,
        image: &AvatarImage,
        refresh_at: Option<u64>,
    ) -> StorageResult<AvatarPublishResult> {
        self.connection.with_transaction(|| {
            if !self.avatar_attempt_current(job)? { return Ok(AvatarPublishResult::Superseded); }
            let result = self.publish_avatar(&job.reference, job.revision, image, refresh_at)?;
            // A newer content revision also releases this attempt; it must not
            // leave a permanently fetching row after losing the publication CAS.
            self.lock()?.execute(
                "UPDATE avatar_acquisition SET state = 0, due = ?1, failures = 0, priority = 0, attempt = NULL WHERE token = ?2",
                params![refresh_at.map(u64_to_i64).transpose()?, job.reference.token],
            ).storage()?;
            Ok(result)
        })
    }

    /// Exponential retries (60s..1h) slow to one daily probe after 16 consecutive
    /// failures, so an extended outage cannot strand a source permanently. The
    /// HTTP helper retains its own bounded per-attempt retry budget. Policy
    /// failures can block until a source change; existing usable bytes are retained.
    pub fn fail_avatar_acquisition(
        &self,
        job: &AvatarAcquisition,
        now: u64,
        retryable: bool,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            if !self.avatar_attempt_current(job)? { return Ok(false); }
            let conn = self.lock()?;
            let failures: u32 = conn.query_row("SELECT failures FROM avatar_acquisition WHERE token = ?1", [&job.reference.token], |r| r.get(0)).storage()?;
            let delay = if failures >= 15 { 24 * 60 * 60 } else { (60_u64 << failures.min(6)).min(3600) };
            let due = retryable.then(|| now.saturating_add(delay)).map(u64_to_i64).transpose()?;
            conn.execute("UPDATE avatar_acquisition SET state = ?1, due = ?2, failures = min(failures + 1, 16), priority = 0, attempt = NULL WHERE token = ?3",
                params![if retryable { 3 } else { 4 }, due, job.reference.token]).storage()?;
            Ok(true)
        })
    }

    fn avatar_attempt_current(&self, job: &AvatarAcquisition) -> StorageResult<bool> {
        self.lock()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM avatar_acquisition q CROSS JOIN chat_presentation_meta m
             WHERE q.token = ?1 AND q.attempt = ?2 AND q.state = 2 AND m.id = 1 AND m.store_epoch = ?3)",
            params![job.reference.token, job.attempt, job.reference.store_epoch], |r| r.get(0),
        ).storage()
    }

    pub fn avatar_acquisition_state(
        &self,
        reference: &AvatarAssetRef,
    ) -> StorageResult<Option<AvatarAcquisitionState>> {
        let value: Option<i64> = self
            .lock()?
            .query_row(
                "SELECT state FROM avatar_acquisition CROSS JOIN chat_presentation_meta m
             WHERE token = ?1 AND m.id = 1 AND m.store_epoch = ?2",
                params![reference.token, reference.store_epoch],
                |r| r.get(0),
            )
            .optional()
            .storage()?;
        value
            .map(|v| match v {
                0 => Ok(AvatarAcquisitionState::Idle),
                1 => Ok(AvatarAcquisitionState::Queued),
                2 => Ok(AvatarAcquisitionState::Fetching),
                3 => Ok(AvatarAcquisitionState::RetryScheduled),
                4 => Ok(AvatarAcquisitionState::Blocked),
                _ => Err(invalid("invalid avatar acquisition state")),
            })
            .transpose()
    }

    /// Current binding for a conversation identity, including its previous source.
    pub fn avatar_identity_reference(
        &self,
        group: &str,
        member: &str,
    ) -> StorageResult<Option<AvatarAssetRef>> {
        let Some(chat) = self.avatar_chat_owner(group)? else {
            return Ok(None);
        };
        self.avatar_reference(&format!("identity:{chat}:{member}"))
    }

    /// Register only an explicitly requested conversation identity. Placeholder
    /// registrations survive until profile data arrives; capacity eviction drops
    /// registration too, so background maintenance cannot refill evicted images.
    pub fn request_identity_avatar_acquisition(
        &self,
        group: &str,
        member: &str,
        selected: &SelectedAvatar,
        version: &ChatPresentationVersion,
    ) -> StorageResult<Option<AvatarAssetRef>> {
        self.connection.with_transaction(|| {
            let chat_owner = self.avatar_chat_owner(group)?.ok_or_else(|| invalid("avatar conversation missing"))?;
            let owner = format!("identity:{chat_owner}:{member}");
            validate_key(&owner)?;
            let current = self.identity_avatar_version_current(&owner, version)?;
            // Preserve the explicit registration even while presentation is
            // adopting a new directory incarnation. Never publish that stale
            // selection or downgrade a newer registration's profile version.
            let reference = if current { self.request_avatar_acquisition(&owner, selected, true)? } else { None };
            let conn = self.lock()?;
            let accessed = next_access(&conn)?;
            conn.execute("INSERT INTO avatar_identity_demand(owner_key, group_id_hex, member_id_hex, accessed, profile_epoch, profile_revision)
                VALUES(?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(owner_key) DO UPDATE SET accessed = excluded.accessed,
                    profile_epoch = CASE WHEN ?7 THEN excluded.profile_epoch ELSE profile_epoch END,
                    profile_revision = CASE WHEN ?7 THEN excluded.profile_revision ELSE profile_revision END",
                params![owner, group, member, accessed, version.store_epoch, u64_to_i64(version.revision)?, current]).storage()?;
            conn.execute("DELETE FROM avatar_identity_demand WHERE owner_key IN
                (SELECT owner_key FROM avatar_identity_demand ORDER BY accessed DESC, owner_key DESC LIMIT -1 OFFSET 2048)", []).storage()?;
            Ok(reference)
        })
    }

    /// One bounded page; never crawls historical roster membership.
    pub fn requested_avatar_identities_after(
        &self,
        after: &str,
    ) -> StorageResult<Vec<AvatarIdentityDemand>> {
        self.lock()?.prepare("SELECT owner_key, group_id_hex, member_id_hex FROM avatar_identity_demand WHERE owner_key > ?1 ORDER BY owner_key LIMIT ?2").storage()?
            .query_map(params![after, AVATAR_IDENTITY_BATCH_LIMIT as i64], |r| Ok(AvatarIdentityDemand { owner: r.get(0)?, group: r.get(1)?, member: r.get(2)? })).storage()?.collect::<Result<Vec<_>,_>>().storage()
    }

    /// Recheck registration under the account transaction after reading the
    /// shared profile. Eviction/removal during preparation must not recreate it.
    pub fn maintain_identity_avatar_acquisition(
        &self,
        identity: &AvatarIdentityDemand,
        selected: &SelectedAvatar,
        version: &ChatPresentationVersion,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            if !self.identity_avatar_version_current(&identity.owner, version)? { return Ok(()); }
            let exists: bool = self
                .lock()?
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM avatar_identity_demand WHERE owner_key = ?1)",
                    [&identity.owner],
                    |r| r.get(0),
                )
                .storage()?;
            if !exists {
                return Ok(());
            }
            let source: Option<String> = self
                .lock()?
                .query_row(
                    "SELECT source_key FROM avatar_assets WHERE owner_key = ?1",
                    [&identity.owner],
                    |r| r.get(0),
                )
                .optional()
                .storage()?;
            let same = match selected {
                SelectedAvatar::RemoteImage { cache_key, .. }
                | SelectedAvatar::EncryptedGroupImage { cache_key, .. } => {
                    source.as_ref() == Some(cache_key)
                }
                SelectedAvatar::Placeholder { .. } => source.is_none(),
            };
            if !same {
                // Preserve a placeholder registration across deleting the old
                // asset, without touching recency on unchanged maintenance.
                let accessed: i64 = self
                    .lock()?
                    .query_row(
                        "SELECT accessed FROM avatar_identity_demand WHERE owner_key = ?1",
                        [&identity.owner],
                        |r| r.get(0),
                    )
                    .storage()?;
                self.request_avatar_acquisition(&identity.owner, selected, false)?;
                self.lock()?
                    .execute(
                        "INSERT OR IGNORE INTO avatar_identity_demand(owner_key, group_id_hex, member_id_hex, accessed, profile_epoch, profile_revision) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                        params![identity.owner, identity.group, identity.member, accessed, version.store_epoch, u64_to_i64(version.revision)?],
                    )
                    .storage()?;
            }
            self.lock()?.execute("UPDATE avatar_identity_demand SET profile_epoch = ?1, profile_revision = ?2 WHERE owner_key = ?3 AND (profile_epoch IS NOT ?1 OR profile_revision <> ?2)",
                params![version.store_epoch, u64_to_i64(version.revision)?, identity.owner]).storage()?;
            Ok(())
        })
    }

    fn identity_avatar_version_current(
        &self,
        owner: &str,
        version: &ChatPresentationVersion,
    ) -> StorageResult<bool> {
        let checkpoint = self.chat_presentation_checkpoint()?;
        if !checkpoint.state.shared_epoch.is_empty()
            && checkpoint.state.shared_epoch != version.store_epoch
        {
            return Ok(false);
        }
        let old: Option<(Vec<u8>, i64)> = self.lock()?.query_row("SELECT profile_epoch, profile_revision FROM avatar_identity_demand WHERE owner_key = ?1", [owner], |r| Ok((r.get(0)?, r.get(1)?))).optional().storage()?;
        let revision = u64_to_i64(version.revision)?;
        Ok(
            old.is_none_or(|(epoch, previous)| {
                epoch != version.store_epoch || previous <= revision
            }),
        )
    }
}

fn owner_for_chat(conn: &Connection, group: &str) -> StorageResult<Option<String>> {
    conn.query_row(
        "SELECT 'chat:' || lower(hex(presentation_row_epoch)) FROM chat_list_rows WHERE group_id_hex = ?1",
        [group], |r| r.get(0),
    ).optional().storage()
}

/// A registered identity, not a roster enumeration. Debug omits identifiers.
pub struct AvatarIdentityDemand {
    pub owner: String,
    pub group: String,
    pub member: String,
}
impl fmt::Debug for AvatarIdentityDemand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvatarIdentityDemand")
            .finish_non_exhaustive()
    }
}
