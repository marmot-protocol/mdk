//! Pure parity subset of the existing smart-folder rules. This module does not
//! capture a selection or read storage, and does not implement legacy folders.
//! Unsupported fields reject the entire automatic rule, even in an otherwise
//! decisive branch. Callers must never interpret that error as a matching rule.
use crate::ChatConversationKind;
use std::collections::HashSet;

/// Kotlin SmartFolderCodec's existing structural limits, not a new wire format.
const MAX_DEPTH: usize = 4;
const MAX_NODES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FolderTruth {
    True,
    False,
    Unknown,
}
impl FolderTruth {
    pub(crate) fn inverted(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
    pub(crate) fn from_bool(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

/// Existing Android field names. Title still explicitly fails admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmartFolderField {
    Unread,
    Mentions,
    Muted,
    Pinned,
    Archived,
    Type,
    Accepted,
    Draft,
    PendingSend,
    Title,
    Participants,
}

/// Typed modes from the existing codec; this is not a serialized payload adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmartFolderMode {
    Present,
    None,
    Direct,
    Group,
    AnyOf,
    AllOf,
    Excludes,
    Contains,
}

#[derive(Clone, PartialEq, Eq)]
pub enum SmartFolderPredicate {
    Group {
        all: bool,
        children: Vec<Self>,
        not: bool,
    },
    Condition {
        field: SmartFolderField,
        mode: SmartFolderMode,
        values: Vec<String>,
        not: bool,
    },
}

// Conditions may carry private participant identities (and eventually title
// text). Debug output is aggregate-only, including invalid/unadmitted inputs.
impl std::fmt::Debug for SmartFolderPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Group { all, children, not } => f
                .debug_struct("Group")
                .field("all", all)
                .field("child_count", &children.len())
                .field("not", not)
                .finish(),
            Self::Condition {
                field,
                mode,
                values,
                not,
            } => f
                .debug_struct("Condition")
                .field("field", field)
                .field("mode", mode)
                .field("value_count", &values.len())
                .field("not", not)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmartFolderError {
    UnsupportedField(SmartFolderField),
    InvalidMode,
    InvalidValues,
    TooDeep,
    TooManyNodes,
}

/// Minimal immutable evidence corresponding to an existing ChatListRow projection.
/// None at the evaluation entry point means the projection is missing, not that
/// each boolean is false. Construct this only from one consistent source snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmartFolderProjection {
    pub has_unread: bool,
    pub manually_marked_unread: bool,
    pub unread_count: u64,
    pub has_unread_mention: bool,
    pub unread_mention_count: u64,
    pub muted: bool,
    pub pinned: bool,
    pub archived: bool,
    pub conversation_kind: ChatConversationKind,
}

/// Source-owned accepted-state evidence from one consistent projection/group snapshot.
/// The caller must leave this absent when either source is unavailable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmartFolderAccepted {
    pub invite_confirmation_unresolved: bool,
    pub removed: bool,
    pub pending_confirmation: bool,
    pub self_is_member: bool,
    pub leave_request_pending: bool,
    pub disbanding: bool,
    pub disbanded: bool,
    pub unrecoverable: bool,
}

/// Borrowed, already folded native member IDs. A presentation-only peer is not
/// the resolved roster peer used by smart participant matching. No full roster
/// is cloned per condition; only the selected keys are looked up.
pub struct SmartFolderParticipants<'a> {
    pub folded_member_ids: &'a HashSet<String>,
    pub resolved_peer: Option<&'a str>,
    pub roster_nonempty: bool,
    pub conversation_kind: ChatConversationKind,
}

/// Immutable optional facts supplied by their native source owner. This pure
/// layer does not establish storage readiness, read drafts, or infer host-only
/// optimistic state. `selected_preview_has_draft` is the source's selected
/// preview truth, not EXISTS(message_drafts). `sending` proves only a positive
/// Sending indicator: false/missing never proves account-wide outbox absence.
#[derive(Default)]
pub struct SmartFolderContext<'a> {
    pub projection: Option<&'a SmartFolderProjection>,
    pub accepted: Option<SmartFolderAccepted>,
    pub selected_preview_has_draft: Option<bool>,
    pub sending: Option<bool>,
    pub participants: Option<SmartFolderParticipants<'a>>,
}

/// Validate every branch before applying three-valued matching. Invalid or
/// unsupported branches cannot hide behind an earlier True/False result.
pub fn evaluate_smart_folder(
    predicate: &SmartFolderPredicate,
    projection: Option<&SmartFolderProjection>,
) -> Result<FolderTruth, SmartFolderError> {
    evaluate_smart_folder_with_context(
        predicate,
        &SmartFolderContext {
            projection,
            ..Default::default()
        },
    )
}

/// Evaluate only supplied native evidence; missing context remains Unknown.
/// Callers must establish complete-scope readiness separately before capture.
pub fn evaluate_smart_folder_with_context(
    predicate: &SmartFolderPredicate,
    context: &SmartFolderContext<'_>,
) -> Result<FolderTruth, SmartFolderError> {
    validate(predicate, 0, &mut 0)?;
    Ok(evaluate(predicate, context))
}

/// Apply membership only after native eligibility has been established. Manual
/// membership bypasses an automatic rule, but never missing/hidden/blocked state
/// or an explicit exclusion. An invalid automatic rule contributes no members.
/// The caller retains any evaluation error for admission/readiness reporting.
pub fn smart_folder_member(
    eligible: bool,
    manual: bool,
    excluded: bool,
    automatic: Result<FolderTruth, SmartFolderError>,
) -> bool {
    eligible && !excluded && (manual || automatic == Ok(FolderTruth::True))
}

fn validate(
    predicate: &SmartFolderPredicate,
    depth: usize,
    count: &mut usize,
) -> Result<(), SmartFolderError> {
    validate_for_capture(predicate, depth, count, false)
}

/// Complete-capture admission also supports deferred host-rendered Title leaves.
pub(crate) fn validate_for_capture(
    predicate: &SmartFolderPredicate,
    depth: usize,
    count: &mut usize,
    presentation: bool,
) -> Result<(), SmartFolderError> {
    if depth > MAX_DEPTH {
        return Err(SmartFolderError::TooDeep);
    }
    *count += 1;
    if *count > MAX_NODES {
        return Err(SmartFolderError::TooManyNodes);
    }
    match predicate {
        SmartFolderPredicate::Group { children, .. } => {
            for child in children {
                validate_for_capture(child, depth + 1, count, presentation)?;
            }
        }
        SmartFolderPredicate::Condition {
            field,
            mode,
            values,
            ..
        } => {
            let valid_mode = match field {
                SmartFolderField::Unread
                | SmartFolderField::Mentions
                | SmartFolderField::Muted
                | SmartFolderField::Pinned
                | SmartFolderField::Archived
                | SmartFolderField::Accepted
                | SmartFolderField::Draft
                | SmartFolderField::PendingSend => {
                    matches!(mode, SmartFolderMode::Present | SmartFolderMode::None)
                }
                SmartFolderField::Type => {
                    matches!(mode, SmartFolderMode::Direct | SmartFolderMode::Group)
                }
                SmartFolderField::Participants => matches!(
                    mode,
                    SmartFolderMode::AnyOf | SmartFolderMode::AllOf | SmartFolderMode::Excludes
                ),
                SmartFolderField::Title if presentation => *mode == SmartFolderMode::Contains,
                field => return Err(SmartFolderError::UnsupportedField(*field)),
            };
            if !valid_mode {
                return Err(SmartFolderError::InvalidMode);
            }
            if *field == SmartFolderField::Participants {
                // Enforce the codec cardinality before allocating the duplicate check.
                if values.is_empty() || values.len() > 64 {
                    return Err(SmartFolderError::InvalidValues);
                }
                let unique: HashSet<_> = values.iter().collect();
                if unique.len() != values.len()
                    || values.iter().any(|key| {
                        key.len() != 64
                            || !key
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                {
                    return Err(SmartFolderError::InvalidValues);
                }
            } else if *field == SmartFolderField::Title {
                // Kotlin codec limits TEXT by UTF-16 code units, not Unicode scalars.
                if values.len() != 1
                    || values[0].encode_utf16().count() > 256
                    || values[0].chars().all(|c| {
                        matches!(c, '\u{0009}'..='\u{000d}' | '\u{001c}'..='\u{0020}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
                    })
                {
                    return Err(SmartFolderError::InvalidValues);
                }
            } else if !values.is_empty() {
                return Err(SmartFolderError::InvalidValues);
            }
        }
    }
    Ok(())
}

fn evaluate(predicate: &SmartFolderPredicate, context: &SmartFolderContext<'_>) -> FolderTruth {
    match predicate {
        SmartFolderPredicate::Group { all, children, not } => {
            // Even NOT(empty) remains unknown, preventing accidental MatchAll.
            if children.is_empty() {
                return FolderTruth::Unknown;
            }
            let mut unknown = false;
            let mut truth = FolderTruth::from_bool(*all);
            for child in children {
                match evaluate(child, context) {
                    FolderTruth::False if *all => {
                        truth = FolderTruth::False;
                        break;
                    }
                    FolderTruth::True if !*all => {
                        truth = FolderTruth::True;
                        break;
                    }
                    FolderTruth::Unknown => unknown = true,
                    _ => {}
                }
            }
            if unknown && truth == FolderTruth::from_bool(*all) {
                truth = FolderTruth::Unknown;
            }
            if *not { truth.inverted() } else { truth }
        }
        SmartFolderPredicate::Condition {
            field,
            mode,
            values,
            not,
        } => {
            let mut truth = match field {
                SmartFolderField::Accepted => context.accepted.map_or(FolderTruth::Unknown, |a| {
                    if a.invite_confirmation_unresolved {
                        FolderTruth::Unknown
                    } else {
                        FolderTruth::from_bool(
                            !a.removed
                                && !a.pending_confirmation
                                && a.self_is_member
                                && !a.leave_request_pending
                                && !a.disbanding
                                && !a.disbanded
                                && !a.unrecoverable,
                        )
                    }
                }),
                SmartFolderField::Draft => context
                    .selected_preview_has_draft
                    .map_or(FolderTruth::Unknown, FolderTruth::from_bool),
                SmartFolderField::PendingSend => {
                    if context.sending == Some(true) {
                        FolderTruth::True
                    } else {
                        FolderTruth::Unknown
                    }
                }
                SmartFolderField::Participants => {
                    participant_truth(context.participants.as_ref(), values, *mode)
                }
                _ => context.projection.map_or(FolderTruth::Unknown, |p| {
                    let value = match field {
                        SmartFolderField::Unread => {
                            p.has_unread || p.manually_marked_unread || p.unread_count > 0
                        }
                        SmartFolderField::Mentions => {
                            p.has_unread_mention || p.unread_mention_count > 0
                        }
                        SmartFolderField::Muted => p.muted,
                        SmartFolderField::Pinned => p.pinned,
                        SmartFolderField::Archived => p.archived,
                        SmartFolderField::Type => match p.conversation_kind {
                            ChatConversationKind::Unknown => return FolderTruth::Unknown,
                            ChatConversationKind::Direct => *mode == SmartFolderMode::Direct,
                            ChatConversationKind::Group => *mode == SmartFolderMode::Group,
                        },
                        // validate() rejects these before evaluation of any branch.
                        _ => unreachable!("unsupported smart-folder field passed validation"),
                    };
                    FolderTruth::from_bool(value)
                }),
            };
            if *mode == SmartFolderMode::None {
                truth = truth.inverted();
            }
            if *not { truth.inverted() } else { truth }
        }
    }
}

fn participant_truth(
    evidence: Option<&SmartFolderParticipants<'_>>,
    values: &[String],
    mode: SmartFolderMode,
) -> FolderTruth {
    let Some(evidence) = evidence else {
        return FolderTruth::Unknown;
    };
    let found = values
        .iter()
        .filter(|key| {
            evidence.folded_member_ids.contains(key.as_str())
                || evidence.resolved_peer == Some(key.as_str())
        })
        .count();
    let complete = evidence.roster_nonempty
        && match evidence.conversation_kind {
            ChatConversationKind::Group => true,
            ChatConversationKind::Direct => evidence.resolved_peer.is_some(),
            ChatConversationKind::Unknown => false,
        };
    match mode {
        SmartFolderMode::AnyOf if found > 0 => FolderTruth::True,
        SmartFolderMode::AllOf if found == values.len() => FolderTruth::True,
        SmartFolderMode::Excludes if found > 0 => FolderTruth::False,
        SmartFolderMode::AnyOf | SmartFolderMode::AllOf if complete => FolderTruth::False,
        SmartFolderMode::Excludes if complete => FolderTruth::True,
        _ => FolderTruth::Unknown,
    }
}

#[cfg(test)]
mod compiled;
#[cfg(test)]
pub(crate) use compiled::CompiledNativeFolder;

#[cfg(test)]
mod tests;
