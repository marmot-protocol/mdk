//! Exact owned inputs for the existing host search predicate. No snippets,
//! media references/keys, profile requests or native Unicode implementation.
use super::*;
#[derive(Clone, PartialEq, Eq)]
pub struct SearchScope {
    pub raw_query: String,
    /// Frozen Kotlin-trimmed query, passed to the existing native LIKE gate.
    pub sql_needle: Option<String>,
    /// Existing sender/date/content filter mode. Its immutable constraint values
    /// belong to the same HostContextIdentity as all host answers.
    pub message_only: bool,
}
impl fmt::Debug for SearchScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchScope")
            .field("message_only", &self.message_only)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct SearchPreviewMessage {
    pub message_id_hex: String,
    /// Existing host-owned media preview text, only for this exact message.
    /// This is metadata-search input, never a body-match operand.
    pub resolved_media_preview_fallback: Option<String>,
    pub plaintext: String,
    pub kind: u64,
    pub deleted: bool,
    pub attachment_kind: Option<storage_sqlite::ChatListAttachmentKind>,
    pub attachment_count: u32,
    pub group_system: Option<storage_sqlite::GroupSystemEventProjection>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct SearchMessage {
    pub message_id_hex: String,
    pub sender: String,
    /// Full text is required for Kotlin isNotBlank and LINKS classification.
    /// Only bodyMatches applies its existing 4096 UTF-16-unit scan cap.
    pub plaintext: String,
    pub kind: u64,
    pub timeline_at: u64,
    pub deleted: bool,
    pub retention_seconds: Option<u64>,
    pub retention_expires_at: Option<u64>,
    pub retention_expired: bool,
    pub media_types: Vec<String>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct SearchPresentation {
    pub scope: SearchScope,
    pub nostr_group_id_hex: String,
    pub last_message: Option<SearchPreviewMessage>,
    pub messages: Vec<SearchMessage>,
    pub capture_now_ms: i64,
}
macro_rules! redacted_debug { ($($kind:ty),*) => { $(impl fmt::Debug for $kind { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str(concat!(stringify!($kind), " { redacted }")) } })* }; }
redacted_debug!(SearchPreviewMessage, SearchMessage, SearchPresentation);
impl SearchPreviewMessage {
    pub(crate) fn text_bytes(&self) -> Option<usize> {
        let mut total = self
            .plaintext
            .len()
            .checked_add(self.message_id_hex.len())?
            .checked_add(
                self.resolved_media_preview_fallback
                    .as_ref()
                    .map_or(0, String::len),
            )?;
        if let Some(system) = &self.group_system {
            for text in [
                Some(system.system_type.as_str()),
                Some(system.text.as_str()),
                system.actor_display_name.as_deref(),
                system.subject_display_name.as_deref(),
                system.actor_account_id_hex.as_deref(),
                system.subject_account_id_hex.as_deref(),
                system.name.as_deref(),
                system.old_name.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                total = total.checked_add(text.len())?;
            }
        }
        Some(total)
    }
    pub(crate) fn try_owned_copy(&self) -> Result<Self, PresentationError> {
        Ok(Self {
            message_id_hex: owned_text(&self.message_id_hex)?,
            resolved_media_preview_fallback: self
                .resolved_media_preview_fallback
                .as_deref()
                .map(owned_text)
                .transpose()?,
            plaintext: owned_text(&self.plaintext)?,
            kind: self.kind,
            deleted: self.deleted,
            attachment_kind: self.attachment_kind,
            attachment_count: self.attachment_count,
            group_system: self
                .group_system
                .as_ref()
                .map(|event| -> Result<_, PresentationError> {
                    let optional =
                        |value: &Option<String>| value.as_deref().map(owned_text).transpose();
                    Ok(storage_sqlite::GroupSystemEventProjection {
                        provenance: event.provenance,
                        actor_display_name: optional(&event.actor_display_name)?,
                        subject_display_name: optional(&event.subject_display_name)?,
                        system_type: owned_text(&event.system_type)?,
                        text: owned_text(&event.text)?,
                        actor_account_id_hex: optional(&event.actor_account_id_hex)?,
                        subject_account_id_hex: optional(&event.subject_account_id_hex)?,
                        name: optional(&event.name)?,
                        old_name: optional(&event.old_name)?,
                        old_retention_seconds: event.old_retention_seconds,
                        new_retention_seconds: event.new_retention_seconds,
                    })
                })
                .transpose()?,
        })
    }
}
impl SearchPresentation {
    pub(super) fn same_required_inputs(&self, old: &Self) -> bool {
        // Literal time is not itself a predicate input once every temporal
        // decision is represented by source-owned per-message expiry truth.
        self.scope == old.scope
            && self.nostr_group_id_hex == old.nostr_group_id_hex
            && self.last_message == old.last_message
            && self.messages == old.messages
    }
    pub(crate) fn text_bytes(&self) -> Option<usize> {
        let mut total = self
            .scope
            .raw_query
            .len()
            .checked_add(self.scope.sql_needle.as_ref().map_or(0, String::len))?
            .checked_add(self.nostr_group_id_hex.len())?;
        if let Some(preview) = &self.last_message {
            total = total.checked_add(preview.text_bytes()?)?;
        }
        for message in &self.messages {
            for text in std::iter::once(message.message_id_hex.as_str())
                .chain([message.sender.as_str(), message.plaintext.as_str()])
                .chain(message.media_types.iter().map(String::as_str))
            {
                total = total.checked_add(text.len())?;
            }
        }
        Some(total)
    }
    pub(crate) fn other_bytes(&self) -> Option<usize> {
        self.messages
            .len()
            .checked_mul(std::mem::size_of::<SearchMessage>() + 128)?
            .checked_add(self.messages.iter().try_fold(0usize, |n, m| {
                n.checked_add(
                    m.media_types
                        .len()
                        .checked_mul(std::mem::size_of::<String>() + 32)?,
                )
            })?)?
            .checked_add(std::mem::size_of::<Self>() + 512)
    }
    pub(super) fn try_owned_copy(&self) -> Result<Self, PresentationError> {
        let mut messages = Vec::new();
        messages
            .try_reserve_exact(self.messages.len())
            .map_err(|_| PresentationError::ResourceExhausted)?;
        for message in &self.messages {
            let mut media_types = Vec::new();
            media_types
                .try_reserve_exact(message.media_types.len())
                .map_err(|_| PresentationError::ResourceExhausted)?;
            for mime in &message.media_types {
                media_types.push(owned_text(mime)?);
            }
            messages.push(SearchMessage {
                message_id_hex: owned_text(&message.message_id_hex)?,
                sender: owned_text(&message.sender)?,
                plaintext: owned_text(&message.plaintext)?,
                media_types,
                kind: message.kind,
                timeline_at: message.timeline_at,
                deleted: message.deleted,
                retention_seconds: message.retention_seconds,
                retention_expires_at: message.retention_expires_at,
                retention_expired: message.retention_expired,
            });
        }
        // Group-system parsing is already bounded to16KiB by its source owner.
        // Only this bounded typed scalar object is cloned; no media reference.
        let last_message = self
            .last_message
            .as_ref()
            .map(SearchPreviewMessage::try_owned_copy)
            .transpose()?;
        Ok(Self {
            scope: SearchScope {
                raw_query: owned_text(&self.scope.raw_query)?,
                sql_needle: self
                    .scope
                    .sql_needle
                    .as_deref()
                    .map(owned_text)
                    .transpose()?,
                message_only: self.scope.message_only,
            },
            nostr_group_id_hex: owned_text(&self.nostr_group_id_hex)?,
            last_message,
            messages,
            capture_now_ms: self.capture_now_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn search_required_inputs_ignore_only_literal_clock_and_preserve_full_text_and_expiry_truth() {
        let value = SearchPresentation {
            scope: SearchScope {
                raw_query: "private-query-sentinel".into(),
                sql_needle: Some("private-query-sentinel".into()),
                message_only: true,
            },
            nostr_group_id_hex: "private-route-sentinel".into(),
            last_message: None,
            messages: vec![SearchMessage {
                message_id_hex: "private-message-sentinel".into(),
                sender: "private-sender-sentinel".into(),
                plaintext: format!("{} https://private-body-sentinel", "x".repeat(4500)),
                kind: 9,
                timeline_at: 1,
                deleted: false,
                retention_seconds: Some(2),
                retention_expires_at: Some(3),
                retention_expired: false,
                media_types: vec!["private-mime-sentinel".into()],
            }],
            capture_now_ms: 1000,
        };
        let mut later = value.try_owned_copy().unwrap();
        later.capture_now_ms = 2999;
        assert!(later.same_required_inputs(&value));
        assert_eq!(later.messages[0].plaintext, value.messages[0].plaintext);
        later.messages[0].retention_expired = true;
        later.capture_now_ms = 3000;
        assert!(!later.same_required_inputs(&value));
        later = value.try_owned_copy().unwrap();
        later.messages[0].retention_expires_at = Some(4);
        assert!(!later.same_required_inputs(&value));
        later = value.try_owned_copy().unwrap();
        later.messages[0].media_types.clear();
        assert!(!later.same_required_inputs(&value));
        later = value.try_owned_copy().unwrap();
        later.messages[0].sender.push('x');
        assert!(!later.same_required_inputs(&value));
        later = value.try_owned_copy().unwrap();
        later.messages[0].plaintext.push('x');
        assert!(!later.same_required_inputs(&value));
        later = value.try_owned_copy().unwrap();
        later.scope.message_only = false;
        assert!(!later.same_required_inputs(&value));
        assert!(
            !format!("{value:?} {:?} {:?}", value.scope, value.messages[0]).contains("sentinel")
        );
    }
    #[test]
    fn search_text_budget_refuses_full_oversized_body_without_truncation() {
        let value = SearchPresentation {
            scope: SearchScope {
                raw_query: String::new(),
                sql_needle: None,
                message_only: true,
            },
            nostr_group_id_hex: String::new(),
            last_message: None,
            messages: vec![SearchMessage {
                message_id_hex: String::new(),
                sender: String::new(),
                plaintext: "x".repeat(TEXT_BUDGET + 1),
                kind: 9,
                timeline_at: 0,
                deleted: false,
                retention_seconds: None,
                retention_expires_at: None,
                retention_expired: false,
                media_types: Vec::new(),
            }],
            capture_now_ms: 0,
        };
        let mut budget = CaptureBudget::default();
        assert_eq!(
            budget.charge(value.text_bytes().unwrap(), value.other_bytes().unwrap()),
            Err(PresentationError::ResourceExhausted)
        );
        assert_eq!(value.messages[0].plaintext.len(), TEXT_BUDGET + 1);
    }
}
