//! Typed interpretation of group reports and shared review decisions.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportReason {
    Nudity,
    Malware,
    Profanity,
    Illegal,
    Spam,
    Impersonation,
    Other,
}
impl ReportReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nudity => "nudity",
            Self::Malware => "malware",
            Self::Profanity => "profanity",
            Self::Illegal => "illegal",
            Self::Spam => "spam",
            Self::Impersonation => "impersonation",
            Self::Other => "other",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "nudity" => Self::Nudity,
            "malware" => Self::Malware,
            "profanity" => Self::Profanity,
            "illegal" => Self::Illegal,
            "spam" => Self::Spam,
            "impersonation" => Self::Impersonation,
            "other" => Self::Other,
            _ => return None,
        })
    }
    pub fn valid_explanation(self, explanation: &str) -> bool {
        explanation.len() <= 4096 && (self != Self::Other || !explanation.trim().is_empty())
    }
}

pub fn event_id_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub struct ReportReference<'a> {
    pub target: &'a str,
    pub revision: &'a str,
    pub author: &'a str,
    pub reason: ReportReason,
}
fn one_tag<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a [String]> {
    let mut matching = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|v| v == name));
    let tag = matching.next()?;
    matching.next().is_none().then_some(tag.as_slice())
}
pub fn parse_report<'a>(tags: &'a [Vec<String>], content: &str) -> Option<ReportReference<'a>> {
    let event = one_tag(tags, "e")?;
    let target = event.get(1)?.as_str();
    let author = one_tag(tags, "p")?.get(1)?.as_str();
    let reason = ReportReason::parse(event.get(2)?)?;
    let revision = if tags
        .iter()
        .any(|tag| tag.first().is_some_and(|t| t == "revision"))
    {
        one_tag(tags, "revision")?.get(1)?.as_str()
    } else {
        target
    };
    (event_id_is_valid(target)
        && event_id_is_valid(author)
        && event_id_is_valid(revision)
        && reason.valid_explanation(content))
    .then_some(ReportReference {
        target,
        revision,
        author,
        reason,
    })
}
/// NIP-32 vocabulary for reviewing reports, rather than labeling target content.
pub const REPORT_REVIEW_NAMESPACE: &str = "marmot.report-review.v1";

fn event_targets(tags: &[Vec<String>]) -> Option<Vec<String>> {
    tags.iter()
        .filter(|tag| tag.first().is_some_and(|t| t == "e"))
        .map(|tag| tag.get(1).filter(|id| event_id_is_valid(id)).cloned())
        .collect()
}
/// Kind-1985 dismissal: a label on explicit report ids. Content may explain the
/// label but does not select or override its meaning.
pub fn parse_dismissal(tags: &[Vec<String>], _content: &str) -> Option<Vec<String>> {
    let namespace = one_tag(tags, "L")?;
    let label = one_tag(tags, "l")?;
    if namespace.get(1)?.as_str() != REPORT_REVIEW_NAMESPACE
        || label.get(1)?.as_str() != "dismissed"
        || label.get(2)?.as_str() != REPORT_REVIEW_NAMESPACE
    {
        return None;
    }
    let ids = event_targets(tags)?;
    (!ids.is_empty() && ids.len() <= 100).then_some(ids)
}
/// Kind-4891 admin removal: one original message, including every revision.
pub fn parse_removal(tags: &[Vec<String>], content: &str) -> Option<String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Decision {
        v: u8,
        action: String,
    }
    let decision: Decision = serde_json::from_str(content).ok()?;
    if decision.v != 1 || decision.action != "remove" {
        return None;
    }
    let mut ids = event_targets(tags)?;
    (ids.len() == 1).then(|| ids.remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nip56_categories_and_revision_default_are_strict() {
        let id = "11".repeat(32);
        let author = "22".repeat(32);
        for reason in [
            "nudity",
            "malware",
            "profanity",
            "illegal",
            "spam",
            "impersonation",
            "other",
        ] {
            let tags = vec![
                vec!["e".into(), id.clone(), reason.into()],
                vec!["p".into(), author.clone()],
            ];
            assert_eq!(parse_report(&tags, "explanation").unwrap().revision, id);
            assert_eq!(parse_report(&tags, "").is_some(), reason != "other");
        }
        assert!(!ReportReason::Other.valid_explanation(" \n"));
        assert!(!ReportReason::Spam.valid_explanation(&"a".repeat(4097)));
        let mut tags = vec![
            vec!["e".into(), id.clone(), "spam".into()],
            vec!["p".into(), author],
        ];
        tags.push(vec!["revision".into(), "bad-id".into()]);
        assert!(parse_report(&tags, "").is_none());
        tags.pop();
        tags.push(tags[0].clone());
        assert!(parse_report(&tags, "").is_none());
    }
    #[test]
    fn dismissal_labels_are_namespaced_and_bounded() {
        let mut tags = vec![
            vec!["L".into(), REPORT_REVIEW_NAMESPACE.into()],
            vec![
                "l".into(),
                "dismissed".into(),
                REPORT_REVIEW_NAMESPACE.into(),
            ],
            vec!["e".into(), "11".repeat(32)],
        ];
        assert!(parse_dismissal(&tags, "").is_some());
        assert!(parse_dismissal(&tags, "optional explanation").is_some());
        tags[1][1] = "remove".into();
        assert!(parse_dismissal(&tags, "").is_none());
        tags[1][1] = "dismissed".into();
        tags[1][2] = "other.namespace".into();
        assert!(parse_dismissal(&tags, "").is_none());
        tags[1][2] = REPORT_REVIEW_NAMESPACE.into();
        tags.extend(vec![tags[2].clone(); 100]);
        assert!(parse_dismissal(&tags, "").is_none());
        assert!(parse_dismissal(&[], r#"{"v":1,"action":"dismiss"}"#).is_none());
    }
    #[test]
    fn removal_version_action_and_single_target_are_strict() {
        let tags = vec![vec!["e".into(), "11".repeat(32)]];
        assert!(parse_removal(&tags, r#"{"v":1,"action":"remove"}"#).is_some());
        for text in [
            r#"{"v":2,"action":"remove"}"#,
            r#"{"v":1,"action":"dismiss"}"#,
            r#"{"v":1,"action":"remove","extra":0}"#,
            r#"{"v":1,"v":1,"action":"remove"}"#,
        ] {
            assert!(parse_removal(&tags, text).is_none());
        }
        assert!(parse_removal(&vec![tags[0].clone(); 2], r#"{"v":1,"action":"remove"}"#).is_none());
    }
}
