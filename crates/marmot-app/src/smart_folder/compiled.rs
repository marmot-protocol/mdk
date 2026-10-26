//! Private integration only: a validated whole-tree union, decoded once per row.
use super::*;
use std::collections::HashMap;
use storage_sqlite::{SelectedMemberKeys, SelectionContextRequest, SelectionSourceContext};

pub(crate) struct CompiledNativeFolder {
    root: Node,
    pub keys: Option<SelectedMemberKeys>,
    pub request: SelectionContextRequest,
}
enum Node {
    Group {
        all: bool,
        children: Vec<Node>,
        not: bool,
    },
    Members {
        indices: Vec<usize>,
        mode: SmartFolderMode,
        not: bool,
    },
    Scalar(SmartFolderPredicate),
}
impl CompiledNativeFolder {
    pub fn new(predicate: &SmartFolderPredicate) -> Result<Self, SmartFolderError> {
        validate(predicate, 0, &mut 0)?;
        let mut keys = Vec::new();
        let mut lookup = HashMap::new();
        let mut request = SelectionContextRequest::default();
        let root = compile(predicate, &mut keys, &mut lookup, &mut request)?;
        // The source validator permits at most64 nodes and64 values per leaf.
        const {
            assert!(MAX_NODES * 64 <= storage_sqlite::MAX_SELECTED_MEMBER_KEYS);
        }
        let keys = if keys.is_empty() {
            None
        } else {
            Some(SelectedMemberKeys::new(&keys).map_err(|_| SmartFolderError::InvalidValues)?)
        };
        Ok(Self {
            root,
            keys,
            request,
        })
    }
    pub fn matches(&self, context: &SelectionSourceContext<'_>) -> bool {
        evaluate_node(&self.root, context) == FolderTruth::True
    }
}
fn compile(
    predicate: &SmartFolderPredicate,
    keys: &mut Vec<[u8; 32]>,
    lookup: &mut HashMap<[u8; 32], usize>,
    request: &mut SelectionContextRequest,
) -> Result<Node, SmartFolderError> {
    Ok(match predicate {
        SmartFolderPredicate::Group { all, children, not } => Node::Group {
            all: *all,
            not: *not,
            children: children
                .iter()
                .map(|child| compile(child, keys, lookup, request))
                .collect::<Result<_, _>>()?,
        },
        SmartFolderPredicate::Condition {
            field,
            mode,
            values,
            not,
        } => match field {
            SmartFolderField::Accepted
            | SmartFolderField::PendingSend
            | SmartFolderField::Title => {
                return Err(SmartFolderError::UnsupportedField(*field));
            }
            SmartFolderField::Participants => {
                let mut indices = Vec::with_capacity(values.len());
                for value in values {
                    let mut key = [0; 32];
                    hex::decode_to_slice(value, &mut key)
                        .map_err(|_| SmartFolderError::InvalidValues)?;
                    let index = *lookup.entry(key).or_insert_with(|| {
                        let index = keys.len();
                        keys.push(key);
                        index
                    });
                    indices.push(index);
                }
                Node::Members {
                    indices,
                    mode: *mode,
                    not: *not,
                }
            }
            _ => {
                request.draft |= *field == SmartFolderField::Draft;
                Node::Scalar(predicate.clone())
            }
        },
    })
}
fn evaluate_node(node: &Node, context: &SelectionSourceContext<'_>) -> FolderTruth {
    match node {
        Node::Group { all, children, not } => {
            if children.is_empty() {
                return FolderTruth::Unknown;
            }
            let mut unknown = false;
            let mut truth = FolderTruth::from_bool(*all);
            for child in children {
                match evaluate_node(child, context) {
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
        Node::Members { indices, mode, not } => {
            let Some(members) = context.selected_members else {
                return FolderTruth::Unknown;
            };
            let found = indices
                .iter()
                .filter(|index| members.contains(**index))
                .count();
            let complete = members.roster_nonempty()
                && match context.projection.conversation_kind {
                    ChatConversationKind::Group => true,
                    ChatConversationKind::Direct => members.peer_present(),
                    ChatConversationKind::Unknown => false,
                };
            let truth = match mode {
                SmartFolderMode::AnyOf if found > 0 => FolderTruth::True,
                SmartFolderMode::AllOf if found == indices.len() => FolderTruth::True,
                SmartFolderMode::Excludes if found > 0 => FolderTruth::False,
                SmartFolderMode::AnyOf | SmartFolderMode::AllOf if complete => FolderTruth::False,
                SmartFolderMode::Excludes if complete => FolderTruth::True,
                _ => FolderTruth::Unknown,
            };
            if *not { truth.inverted() } else { truth }
        }
        Node::Scalar(predicate) => {
            let p = context.projection;
            let projection = SmartFolderProjection {
                has_unread: false,
                manually_marked_unread: p.manually_marked_unread,
                unread_count: p.unread_count,
                has_unread_mention: false,
                unread_mention_count: p.unread_mention_count,
                muted: p.muted,
                pinned: p.pinned,
                archived: p.archived,
                conversation_kind: p.conversation_kind,
            };
            evaluate(
                predicate,
                &SmartFolderContext {
                    projection: Some(&projection),
                    selected_preview_has_draft: context.selected_preview_has_draft,
                    ..Default::default()
                },
            )
        }
    }
}
