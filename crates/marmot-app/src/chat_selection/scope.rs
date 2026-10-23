//! Closed membership expressions for the existing offered chat-list scopes.
//! IDs below are frozen preference scopes, never caller-supplied SQL candidates.
use super::presentation::{
    CaptureBudget, PresentationError, PresentationLeaf, PresentationLeafKind, SearchScope,
    owned_text,
};
use crate::smart_folder::{
    FolderTruth, SmartFolderField, SmartFolderMode, SmartFolderPredicate, validate_for_capture,
};
use std::collections::{HashMap, HashSet};
use storage_sqlite::{ChatConversationKind, SelectedMemberKeys, SelectionContextRequest};

#[derive(Clone)]
pub struct ScopeRequest {
    pub selected_folder: Option<FolderScope>,
    /// None means no folder filter; Some(empty) is an explicitly empty union.
    pub filter_folders: Option<Vec<FolderScope>>,
    pub named_chats: Option<HashSet<String>>,
    pub direct: bool,
    pub groups: bool,
    pub search: Option<SearchScope>,
}
#[derive(Clone)]
pub struct FolderScope {
    pub manual: HashSet<String>,
    pub excluded: HashSet<String>,
    pub automatic: AutomaticRule,
}
#[derive(Clone)]
pub enum AutomaticRule {
    /// Also the existing invalid-smart-payload fallback: manual members only.
    ManualOnly,
    Smart(SmartFolderPredicate),
    Legacy(LegacyRule),
}
#[derive(Clone)]
pub struct LegacyRule {
    pub members: Vec<String>,
    /// Host codec trims with Kotlin and freezes this input before capture.
    pub keyword: Option<String>,
    pub include_all: bool,
    pub unread_only: bool,
    pub unread_mentions_only: bool,
    pub pinned_only: bool,
    pub groups_only: bool,
    pub direct_only: bool,
    pub archived_only: bool,
    pub include_muted: bool,
}
impl std::fmt::Debug for ScopeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopeRequest")
            .field("selected_folder", &self.selected_folder.is_some())
            .field(
                "filter_folder_count",
                &self.filter_folders.as_ref().map(Vec::len),
            )
            .finish_non_exhaustive()
    }
}
#[derive(Debug, thiserror::Error)]
pub(crate) enum ScopeError {
    #[error("selection scope contains an invalid identity or legacy criterion")]
    Invalid,
    #[error(transparent)]
    Resources(#[from] PresentationError),
}
/// Leaf indexing is request-wide, not a new per-request64-leaf limit. The
/// existing structural validator still runs independently for each smart rule.
pub(crate) struct CompiledScope {
    pub selected: Option<CompiledFolder>,
    pub filter_folders: Option<Vec<CompiledFolder>>,
    pub named_chats: Option<HashSet<String>>,
    pub direct: bool,
    pub groups: bool,
    pub search: Option<SearchScope>,
    pub search_slot: Option<u32>,
    pub keys: Option<SelectedMemberKeys>,
    pub request: SelectionContextRequest,
    pub presentation: Vec<PresentationLeaf>,
    pub native: Vec<NativeLeaf>,
    pub direct_slot: Option<u32>,
    pub budget: CaptureBudget,
    pub needs_roster: bool,
}
pub(crate) struct CompiledFolder {
    manual: HashSet<String>,
    excluded: HashSet<String>,
    automatic: Node,
}
pub(crate) enum NativeLeaf {
    Smart(SmartFolderPredicate),
    Members {
        indices: Vec<usize>,
        mode: SmartFolderMode,
        not: bool,
    },
    LegacyMembers(Vec<usize>),
    LegacyAttention {
        unread: bool,
        mentions: bool,
        pinned: bool,
    },
    LegacyArchive(bool),
    LegacyUnmuted,
}
enum Node {
    Constant(FolderTruth),
    Group {
        all: bool,
        not: bool,
        children: Vec<Node>,
    },
    Native(usize),
    Presentation {
        slot: u32,
        not: bool,
    },
    Direct {
        direct: bool,
        group: bool,
    },
}
struct Builder {
    keys: Vec<Vec<u8>>,
    lookup: HashMap<Vec<u8>, usize>,
    request: SelectionContextRequest,
    presentation: Vec<PresentationLeaf>,
    native: Vec<NativeLeaf>,
    budget: CaptureBudget,
    needs_direct: bool,
    needs_roster: bool,
}
impl Builder {
    fn native(&mut self, leaf: NativeLeaf) -> Result<Node, ScopeError> {
        self.budget.charge(0, 256)?;
        self.native
            .try_reserve(1)
            .map_err(|_| PresentationError::ResourceExhausted)?;
        let slot = self.native.len();
        self.native.push(leaf);
        Ok(Node::Native(slot))
    }
    fn presentation(
        &mut self,
        kind: PresentationLeafKind,
        needle: &str,
        not: bool,
    ) -> Result<Node, ScopeError> {
        self.budget.charge(needle.len(), 128)?;
        let slot = u32::try_from(self.presentation.len())
            .map_err(|_| PresentationError::ResourceExhausted)?;
        self.presentation
            .try_reserve(1)
            .map_err(|_| PresentationError::ResourceExhausted)?;
        self.presentation.push(PresentationLeaf {
            slot,
            kind,
            needle: owned_text(needle)?,
        });
        Ok(Node::Presentation { slot, not })
    }
    fn members(&mut self, values: &[String], legacy: bool) -> Result<Vec<usize>, ScopeError> {
        self.budget.charge(
            0,
            values
                .len()
                .checked_mul(std::mem::size_of::<usize>())
                .ok_or(PresentationError::ResourceExhausted)?,
        )?;
        let mut indices = Vec::new();
        indices
            .try_reserve_exact(values.len())
            .map_err(|_| PresentationError::ResourceExhausted)?;
        for value in values {
            if legacy
                && (value.is_empty()
                    || value.len() % 2 != 0
                    || !value.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                continue;
            }
            let bytes = value.len() / 2;
            if bytes > self.budget.remaining_total() {
                return Err(PresentationError::ResourceExhausted.into());
            }
            let mut key = Vec::new();
            key.try_reserve_exact(bytes)
                .map_err(|_| PresentationError::ResourceExhausted)?;
            key.resize(bytes, 0);
            hex::decode_to_slice(value, &mut key).map_err(|_| ScopeError::Invalid)?;
            if key.is_empty() {
                return Err(ScopeError::Invalid);
            }
            let index = if let Some(index) = self.lookup.get(&key) {
                *index
            } else {
                self.budget.charge(
                    0,
                    key.len()
                        .checked_mul(3)
                        .and_then(|n| n.checked_add(512))
                        .ok_or(PresentationError::ResourceExhausted)?,
                )?;
                self.keys
                    .try_reserve(1)
                    .map_err(|_| PresentationError::ResourceExhausted)?;
                self.lookup
                    .try_reserve(1)
                    .map_err(|_| PresentationError::ResourceExhausted)?;
                let mut copy = Vec::new();
                copy.try_reserve_exact(key.len())
                    .map_err(|_| PresentationError::ResourceExhausted)?;
                copy.extend_from_slice(&key);
                let index = self.keys.len();
                self.keys.push(copy);
                self.lookup.insert(key, index);
                index
            };
            indices.push(index);
        }
        Ok(indices)
    }
    fn smart(&mut self, rule: &SmartFolderPredicate) -> Result<Node, ScopeError> {
        self.budget.charge(0, 128)?;
        Ok(match rule {
            SmartFolderPredicate::Group { all, children, not } => Node::Group {
                all: *all,
                not: *not,
                children: children
                    .iter()
                    .map(|child| self.smart(child))
                    .collect::<Result<_, _>>()?,
            },
            SmartFolderPredicate::Condition {
                field,
                mode,
                values,
                not,
            } => match field {
                SmartFolderField::Title => {
                    self.presentation(PresentationLeafKind::TitleContains, &values[0], *not)?
                }
                SmartFolderField::Participants => {
                    let indices = self.members(values, false)?;
                    self.native(NativeLeaf::Members {
                        indices,
                        mode: *mode,
                        not: *not,
                    })?
                }
                _ => {
                    self.request.draft |= *field == SmartFolderField::Draft;
                    self.request.accepted_sources |= *field == SmartFolderField::Accepted;
                    self.needs_roster |= *field == SmartFolderField::Accepted;
                    self.native(NativeLeaf::Smart(rule.clone()))?
                }
            },
        })
    }
    fn folder(&mut self, folder: FolderScope) -> Result<CompiledFolder, ScopeError> {
        for id in folder.manual.iter().chain(&folder.excluded) {
            self.budget.charge(id.len(), 96)?;
        }
        let automatic = match folder.automatic {
            AutomaticRule::ManualOnly => Node::Constant(FolderTruth::False),
            AutomaticRule::Smart(rule) => {
                if validate_for_capture(&rule, 0, &mut 0, true).is_ok() {
                    self.smart(&rule)?
                } else {
                    Node::Constant(FolderTruth::False)
                }
            }
            AutomaticRule::Legacy(rule) => self.legacy(rule)?,
        };
        Ok(CompiledFolder {
            manual: folder.manual,
            excluded: folder.excluded,
            automatic,
        })
    }
    fn legacy(&mut self, rule: LegacyRule) -> Result<Node, ScopeError> {
        self.needs_roster |= rule.unread_only || rule.unread_mentions_only;
        self.request.accepted_sources |= rule.unread_only || rule.unread_mentions_only;
        let has_keyword = rule.keyword.as_ref().is_some_and(|s| !s.is_empty());
        let base = if rule.members.is_empty() && !has_keyword {
            Node::Constant(FolderTruth::from_bool(
                rule.include_all
                    || rule.unread_only
                    || rule.unread_mentions_only
                    || rule.pinned_only
                    || rule.groups_only
                    || rule.direct_only
                    || rule.archived_only,
            ))
        } else {
            let text_bytes = rule.members.iter().try_fold(0usize, |sum, value| {
                sum.checked_add(value.len())
                    .ok_or(PresentationError::ResourceExhausted)
            })?;
            if text_bytes > self.budget.remaining_text() {
                return Err(PresentationError::ResourceExhausted.into());
            }
            let indices = self.members(&rule.members, true)?;
            let mut children = vec![self.native(NativeLeaf::LegacyMembers(indices))?];
            for wanted in &rule.members {
                children.push(self.presentation(
                    PresentationLeafKind::LegacyPeerEquals,
                    wanted,
                    false,
                )?);
            }
            if let Some(keyword) = rule.keyword.filter(|s| !s.is_empty()) {
                children.push(self.presentation(
                    PresentationLeafKind::LegacyKeyword,
                    &keyword,
                    false,
                )?);
            }
            Node::Group {
                all: false,
                not: false,
                children,
            }
        };
        let mut children = vec![
            base,
            self.native(NativeLeaf::LegacyArchive(rule.archived_only))?,
            self.native(NativeLeaf::LegacyAttention {
                unread: rule.unread_only,
                mentions: rule.unread_mentions_only,
                pinned: rule.pinned_only,
            })?,
        ];
        if rule.groups_only && rule.direct_only {
            children.push(Node::Constant(FolderTruth::False));
        } else if rule.groups_only || rule.direct_only {
            self.needs_direct = true;
            children.push(Node::Direct {
                direct: rule.direct_only,
                group: rule.groups_only,
            });
        }
        if !rule.include_muted {
            children.push(self.native(NativeLeaf::LegacyUnmuted)?);
        }
        Ok(Node::Group {
            all: true,
            not: false,
            children,
        })
    }
}
impl CompiledScope {
    pub fn new(request: ScopeRequest) -> Result<Self, ScopeError> {
        let mut b = Builder {
            keys: Vec::new(),
            lookup: HashMap::new(),
            request: SelectionContextRequest::default(),
            presentation: Vec::new(),
            native: Vec::new(),
            budget: CaptureBudget::default(),
            needs_direct: request.direct ^ request.groups,
            needs_roster: false,
        };
        let selected = request.selected_folder.map(|f| b.folder(f)).transpose()?;
        let filter_folders = request
            .filter_folders
            .map(|folders| {
                folders
                    .into_iter()
                    .map(|f| b.folder(f))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        if let Some(ids) = &request.named_chats {
            for id in ids {
                b.budget.charge(id.len(), 96)?;
            }
        }
        let direct_slot = if b.needs_direct {
            let node = b.presentation(PresentationLeafKind::IsDirect, "", false)?;
            match node {
                Node::Presentation { slot, .. } => Some(slot),
                _ => unreachable!("issued presentation leaf"),
            }
        } else {
            None
        };
        let search_slot = if let Some(search) = &request.search {
            if let Some(needle) = &search.sql_needle {
                b.budget.charge(needle.len(), 0)?;
            }
            let node =
                b.presentation(PresentationLeafKind::ChatSearch, &search.raw_query, false)?;
            match node {
                Node::Presentation { slot, .. } => Some(slot),
                _ => unreachable!("issued search leaf"),
            }
        } else {
            None
        };
        let keys = if b.keys.is_empty() {
            None
        } else {
            Some(
                SelectedMemberKeys::for_legacy_catalog(&b.keys)
                    .map_err(|_| PresentationError::ResourceExhausted)?,
            )
        };
        Ok(Self {
            selected,
            filter_folders,
            named_chats: request.named_chats.filter(|ids| !ids.is_empty()),
            direct: request.direct,
            groups: request.groups,
            search: request.search,
            search_slot,
            keys,
            request: b.request,
            presentation: b.presentation,
            native: b.native,
            direct_slot,
            budget: b.budget,
            needs_roster: b.needs_roster,
        })
    }
    /// Optional display hints must not turn compact default membership into a
    /// presentation/roster capture. Request them explicitly before a dialog.
    pub fn require_action_hints(&mut self) -> Result<(), PresentationError> {
        self.request.accepted_sources = true;
        if self.direct_slot.is_none() {
            self.budget.charge(0, 128)?;
            let slot = u32::try_from(self.presentation.len())
                .map_err(|_| PresentationError::ResourceExhausted)?;
            self.presentation
                .try_reserve(1)
                .map_err(|_| PresentationError::ResourceExhausted)?;
            self.presentation.push(PresentationLeaf {
                slot,
                kind: PresentationLeafKind::IsDirect,
                needle: String::new(),
            });
            self.direct_slot = Some(slot);
        }
        Ok(())
    }
    pub fn matches(
        &self,
        id: &str,
        native: &[FolderTruth],
        presentation: &HashMap<u32, bool>,
        kind: ChatConversationKind,
        fallback_direct: Option<bool>,
    ) -> bool {
        let is_direct = match kind {
            ChatConversationKind::Direct => Some(true),
            ChatConversationKind::Group => Some(false),
            ChatConversationKind::Unknown => fallback_direct,
        };
        let folder = |f: &CompiledFolder| {
            !f.excluded.contains(id)
                && (f.manual.contains(id)
                    || evaluate(&f.automatic, native, presentation, is_direct) == FolderTruth::True)
        };
        self.search_slot
            .is_none_or(|slot| presentation.get(&slot) == Some(&true))
            && self.selected.as_ref().is_none_or(folder)
            && self
                .filter_folders
                .as_ref()
                .is_none_or(|folders| folders.iter().any(folder))
            && self.named_chats.as_ref().is_none_or(|ids| ids.contains(id))
            && (!(self.direct ^ self.groups)
                || is_direct.is_some_and(|direct| if direct { self.direct } else { self.groups }))
    }
}
fn evaluate(
    node: &Node,
    native: &[FolderTruth],
    presentation: &HashMap<u32, bool>,
    direct: Option<bool>,
) -> FolderTruth {
    match node {
        Node::Constant(truth) => *truth,
        Node::Native(slot) => native.get(*slot).copied().unwrap_or(FolderTruth::Unknown),
        Node::Presentation { slot, not } => {
            let truth = presentation
                .get(slot)
                .copied()
                .map(FolderTruth::from_bool)
                .unwrap_or(FolderTruth::Unknown);
            if *not { truth.inverted() } else { truth }
        }
        Node::Direct {
            direct: want_direct,
            group,
        } => direct
            .map(|direct| FolderTruth::from_bool((!want_direct || direct) && (!group || !direct)))
            .unwrap_or(FolderTruth::Unknown),
        Node::Group { all, not, children } => {
            if children.is_empty() {
                return FolderTruth::Unknown;
            }
            let mut truth = FolderTruth::from_bool(*all);
            let mut unknown = false;
            for child in children {
                match evaluate(child, native, presentation, direct) {
                    FolderTruth::False if *all => {
                        truth = FolderTruth::False;
                        break;
                    }
                    FolderTruth::True if !all => {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> ScopeRequest {
        ScopeRequest {
            selected_folder: None,
            filter_folders: None,
            named_chats: None,
            direct: false,
            groups: false,
            search: None,
        }
    }
    fn folder(automatic: AutomaticRule) -> FolderScope {
        FolderScope {
            manual: HashSet::new(),
            excluded: HashSet::new(),
            automatic,
        }
    }
    fn key(index: u64) -> String {
        let mut key = [0; 32];
        key[24..].copy_from_slice(&index.to_be_bytes());
        hex::encode(key)
    }
    fn members(values: Vec<String>, mode: SmartFolderMode, not: bool) -> SmartFolderPredicate {
        SmartFolderPredicate::Condition {
            field: SmartFolderField::Participants,
            mode,
            values,
            not,
        }
    }
    #[test]
    fn optional_action_hints_do_not_expand_compact_default_capture_requirements() {
        let mut compiled = CompiledScope::new(request()).unwrap();
        assert!(compiled.presentation.is_empty());
        assert!(!compiled.request.accepted_sources);
        assert!(compiled.matches(
            "aa",
            &[],
            &HashMap::new(),
            ChatConversationKind::Unknown,
            None
        ));
        compiled.require_action_hints().unwrap();
        assert!(compiled.request.accepted_sources);
        assert_eq!(compiled.presentation.len(), 1);
        assert_eq!(
            compiled.presentation[0].kind,
            PresentationLeafKind::IsDirect
        );
        assert!(compiled.matches(
            "aa",
            &[],
            &HashMap::new(),
            ChatConversationKind::Unknown,
            None
        ));
        compiled.require_action_hints().unwrap();
        assert_eq!(compiled.presentation.len(), 1);
    }
    #[test]
    fn whole_catalog_exceeds_one_rule_union_without_global_cap() {
        let folders = (0..66)
            .map(|folder_index| {
                folder(AutomaticRule::Smart(members(
                    (0..64).map(|n| key(folder_index * 64 + n)).collect(),
                    SmartFolderMode::AnyOf,
                    false,
                )))
            })
            .collect();
        let compiled = CompiledScope::new(ScopeRequest {
            filter_folders: Some(folders),
            ..request()
        })
        .unwrap();
        let keys = compiled.keys.unwrap();
        assert_eq!(keys.len(), 4224);
        assert_eq!(
            keys.index_of(&hex::decode(key(4096)).unwrap().try_into().unwrap()),
            Some(4096)
        );
        // Per-rule structural limits are unchanged despite the larger catalog.
        let invalid = CompiledScope::new(ScopeRequest {
            selected_folder: Some(folder(AutomaticRule::Smart(members(
                (0..65).map(key).collect(),
                SmartFolderMode::AnyOf,
                false,
            )))),
            ..request()
        })
        .unwrap();
        assert!(invalid.keys.is_none());
        assert!(!invalid.matches(
            "aa",
            &[],
            &HashMap::new(),
            ChatConversationKind::Group,
            None
        ));
    }
    #[test]
    fn intersection_union_manual_and_exclusion_do_not_broaden_scope() {
        let selected = FolderScope {
            manual: HashSet::from(["aa".into(), "bb".into()]),
            excluded: HashSet::from(["bb".into()]),
            automatic: AutomaticRule::ManualOnly,
        };
        let filters = vec![FolderScope {
            manual: HashSet::from(["aa".into(), "bb".into(), "cc".into()]),
            excluded: HashSet::new(),
            automatic: AutomaticRule::ManualOnly,
        }];
        let compiled = CompiledScope::new(ScopeRequest {
            selected_folder: Some(selected),
            filter_folders: Some(filters),
            ..request()
        })
        .unwrap();
        let check = |id| {
            compiled.matches(
                id,
                &[],
                &HashMap::new(),
                ChatConversationKind::Unknown,
                None,
            )
        };
        assert!(check("aa"));
        assert!(!check("bb"));
        assert!(!check("cc"));
        let empty = CompiledScope::new(ScopeRequest {
            filter_folders: Some(vec![]),
            ..request()
        })
        .unwrap();
        assert!(!empty.matches(
            "aa",
            &[],
            &HashMap::new(),
            ChatConversationKind::Direct,
            None
        ));
    }
    #[test]
    fn independent_modes_share_keys_not_truth_or_negation() {
        let rules = [
            members(vec![key(1), key(2)], SmartFolderMode::AnyOf, false),
            members(vec![key(2), key(3)], SmartFolderMode::AllOf, true),
            members(vec![key(1)], SmartFolderMode::Excludes, false),
        ];
        let compiled = CompiledScope::new(ScopeRequest {
            filter_folders: Some(
                rules
                    .into_iter()
                    .map(|rule| folder(AutomaticRule::Smart(rule)))
                    .collect(),
            ),
            ..request()
        })
        .unwrap();
        assert_eq!(compiled.keys.as_ref().unwrap().len(), 3);
        assert_eq!(compiled.native.len(), 3);
        assert!(
            matches!(&compiled.native[0],NativeLeaf::Members{indices,mode:SmartFolderMode::AnyOf,not:false} if indices==&[0,1])
        );
        assert!(
            matches!(&compiled.native[1],NativeLeaf::Members{indices,mode:SmartFolderMode::AllOf,not:true} if indices==&[1,2])
        );
        assert!(
            matches!(&compiled.native[2],NativeLeaf::Members{indices,mode:SmartFolderMode::Excludes,not:false} if indices==&[0])
        );
    }
    #[test]
    fn title_validation_uses_codec_utf16_and_kotlin_blankness() {
        let title = |text: String| SmartFolderPredicate::Condition {
            field: SmartFolderField::Title,
            mode: SmartFolderMode::Contains,
            values: vec![text],
            not: false,
        };
        let compile = |rule| {
            CompiledScope::new(ScopeRequest {
                selected_folder: Some(folder(AutomaticRule::Smart(rule))),
                ..request()
            })
        };
        assert_eq!(
            compile(title("😀".repeat(128))).unwrap().presentation.len(),
            1
        );
        assert!(
            compile(title("😀".repeat(129)))
                .unwrap()
                .presentation
                .is_empty()
        );
        assert!(
            compile(title("\u{001c}\u{00a0}\u{2007}\u{202f}".into()))
                .unwrap()
                .presentation
                .is_empty()
        );
        // NEL is Rust whitespace but not Java/Kotlin Char.isWhitespace.
        assert_eq!(
            compile(title("\u{0085}".into()))
                .unwrap()
                .presentation
                .len(),
            1
        );
        assert!(crate::smart_folder::evaluate_smart_folder(&title("title".into()), None).is_err());
    }
}

#[cfg(test)]
mod repair_tests {
    use super::*;
    fn request() -> ScopeRequest {
        ScopeRequest {
            selected_folder: None,
            filter_folders: None,
            named_chats: None,
            direct: false,
            groups: false,
            search: None,
        }
    }
    #[test]
    fn opaque_preference_criteria_never_nominate_candidates_or_reject_valid_neighbors() {
        let manual = HashSet::from(["aa".into(), "legacy-id".into()]);
        let excluded = HashSet::from(["unrelated legacy exclusion".into()]);
        let compiled = CompiledScope::new(ScopeRequest {
            selected_folder: Some(FolderScope {
                manual,
                excluded,
                automatic: AutomaticRule::ManualOnly,
            }),
            named_chats: Some(HashSet::from(["aa".into(), "legacy-id".into()])),
            ..request()
        })
        .unwrap();
        assert!(compiled.matches(
            "aa",
            &[],
            &HashMap::new(),
            ChatConversationKind::Unknown,
            None
        ));
        assert!(!compiled.matches(
            "bb",
            &[],
            &HashMap::new(),
            ChatConversationKind::Unknown,
            None
        ));
        let invalid = CompiledScope::new(ScopeRequest {
            selected_folder: Some(FolderScope {
                manual: HashSet::from(["aa".into()]),
                excluded: HashSet::new(),
                automatic: AutomaticRule::Smart(SmartFolderPredicate::Condition {
                    field: SmartFolderField::Participants,
                    mode: SmartFolderMode::AnyOf,
                    values: vec!["invalid saved key".into()],
                    not: false,
                }),
            }),
            ..request()
        })
        .unwrap();
        assert!(invalid.keys.is_none());
        assert!(invalid.matches(
            "aa",
            &[],
            &HashMap::new(),
            ChatConversationKind::Unknown,
            None
        ));
        assert!(!invalid.matches(
            "bb",
            &[],
            &HashMap::new(),
            ChatConversationKind::Unknown,
            None
        ));
        let both = CompiledScope::new(ScopeRequest {
            direct: true,
            groups: true,
            named_chats: Some(HashSet::new()),
            ..request()
        })
        .unwrap();
        assert!(both.presentation.is_empty());
        assert!(both.matches(
            "aa",
            &[],
            &HashMap::new(),
            ChatConversationKind::Unknown,
            None
        ));
    }
    #[test]
    fn legacy_unbounded_text_returns_resource_refusal() {
        let rule = LegacyRule {
            members: vec!["a".repeat(16 * 1024 * 1024 + 1)],
            keyword: None,
            include_all: false,
            unread_only: false,
            unread_mentions_only: false,
            pinned_only: false,
            groups_only: false,
            direct_only: false,
            archived_only: false,
            include_muted: true,
        };
        let result = CompiledScope::new(ScopeRequest {
            selected_folder: Some(FolderScope {
                manual: HashSet::new(),
                excluded: HashSet::new(),
                automatic: AutomaticRule::Legacy(rule),
            }),
            ..request()
        });
        assert!(matches!(
            result,
            Err(ScopeError::Resources(PresentationError::ResourceExhausted))
        ));
    }
}

#[cfg(test)]
mod search_tests {
    use super::*;
    #[test]
    fn search_answer_is_conjoined_with_native_owned_scope_and_never_nominates_ids() {
        let compiled = CompiledScope::new(ScopeRequest {
            selected_folder: Some(FolderScope {
                manual: HashSet::from(["aa".into()]),
                excluded: HashSet::new(),
                automatic: AutomaticRule::ManualOnly,
            }),
            filter_folders: None,
            named_chats: None,
            direct: false,
            groups: false,
            search: Some(SearchScope {
                raw_query: "needle".into(),
                sql_needle: Some("needle".into()),
                message_only: false,
            }),
        })
        .unwrap();
        let slot = compiled.search_slot.unwrap();
        assert!(compiled.matches(
            "aa",
            &[],
            &HashMap::from([(slot, true)]),
            ChatConversationKind::Group,
            None
        ));
        assert!(!compiled.matches(
            "bb",
            &[],
            &HashMap::from([(slot, true)]),
            ChatConversationKind::Group,
            None
        ));
        assert!(!compiled.matches(
            "aa",
            &[],
            &HashMap::from([(slot, false)]),
            ChatConversationKind::Group,
            None
        ));
        assert!(!compiled.matches(
            "aa",
            &[],
            &HashMap::new(),
            ChatConversationKind::Group,
            None
        ));
    }
}
