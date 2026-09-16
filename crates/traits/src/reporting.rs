//! Typed interpretation of group reports, dismissal labels, and admin deletion.
use serde::{Deserialize, Serialize};

use crate::app_event::{MARMOT_APP_EVENT_KIND_REMOVE, MARMOT_APP_EVENT_KIND_REVIEW};

/// Only these moderation controls need retained source-state authority.
/// Ordinary app events and author deletion do not create authority retry work.
pub fn requires_source_authority(kind: u64) -> bool {
    matches!(
        kind,
        MARMOT_APP_EVENT_KIND_REVIEW | MARMOT_APP_EVENT_KIND_REMOVE
    )
}

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
}

pub fn event_id_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub struct ReportReference<'a> {
    pub target: &'a str,
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
pub fn parse_report<'a>(tags: &'a [Vec<String>], _content: &str) -> Option<ReportReference<'a>> {
    let event = one_tag(tags, "e")?;
    let target = event.get(1)?.as_str();
    let author = one_tag(tags, "p")?.get(1)?.as_str();
    let reason = ReportReason::parse(event.get(2)?)?;
    (event_id_is_valid(target) && event_id_is_valid(author)).then_some(ReportReference {
        target,
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
    let has_namespace = tags.iter().any(|tag| {
        tag.first().is_some_and(|s| s == "L")
            && tag.get(1).is_some_and(|s| s == REPORT_REVIEW_NAMESPACE)
    });
    let has_label = tags.iter().any(|tag| {
        tag.first().is_some_and(|s| s == "l")
            && tag.get(1).is_some_and(|s| s == "dismissed")
            && tag.get(2).is_some_and(|s| s == REPORT_REVIEW_NAMESPACE)
    });
    if !has_namespace || !has_label {
        return None;
    }
    let ids: Vec<_> = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|s| s == "e"))
        .filter_map(|tag| tag.get(1).filter(|id| event_id_is_valid(id)).cloned())
        .collect();
    (!ids.is_empty()).then_some(ids)
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
    fn tags(values: &[&[&str]]) -> Vec<Vec<String>> {
        values
            .iter()
            .map(|tag| tag.iter().map(|s| (*s).into()).collect())
            .collect()
    }
    #[test]
    fn reports_use_nip56_categories_without_revision_or_explanation_requirements() {
        for reason in [
            ReportReason::Nudity,
            ReportReason::Malware,
            ReportReason::Profanity,
            ReportReason::Illegal,
            ReportReason::Spam,
            ReportReason::Impersonation,
            ReportReason::Other,
        ] {
            let t = tags(&[
                &["e", &"11".repeat(32), reason.as_str()],
                &["p", &"22".repeat(32)],
            ]);
            let parsed = parse_report(&t, "").unwrap();
            assert_eq!(parsed.reason, reason);
            assert_eq!(parsed.target, "11".repeat(32));
        }
        assert!(!requires_source_authority(1984));
        assert!(!requires_source_authority(5));
        assert!(requires_source_authority(1985));
        assert!(requires_source_authority(4891));
    }
    #[test]
    fn dismissal_accepts_additional_labels_and_handles_each_reference_independently() {
        let id = "11".repeat(32);
        let mut t = tags(&[
            &["L", "other"],
            &["L", REPORT_REVIEW_NAMESPACE, "extension"],
            &["l", "dismissed", REPORT_REVIEW_NAMESPACE, "extension"],
            &["l", "other", "other"],
            &["e", "bad"],
            &["e"],
            &["e", &id, "extension"],
        ]);
        assert_eq!(
            parse_dismissal(&t, "optional explanation"),
            Some(vec![id.clone()])
        );
        t.extend((0..101).map(|_| vec!["e".into(), id.clone()]));
        assert_eq!(parse_dismissal(&t, "").unwrap().len(), 102);
        assert!(parse_dismissal(&tags(&[&["e", &id]]), "dismissed").is_none());
    }
    #[test]
    fn removal_requires_one_reference_and_exact_versioned_json() {
        let id = "ab".repeat(32);
        let t = tags(&[&["e", &id, "extension"], &["other", "ignored"]]);
        assert_eq!(
            parse_removal(&t, r#"{"v":1,"action":"remove"}"#),
            Some(id.clone())
        );
        for content in [
            r#"{"v":1,"v":1,"action":"remove"}"#,
            r#"{"v":1.0,"action":"remove"}"#,
            r#"{"v":1,"action":"remove","extra":0}"#,
            r#"{"v":2,"action":"remove"}"#,
            r#"{"v":1,"action":"dismiss"}"#,
        ] {
            assert!(parse_removal(&t, content).is_none(), "{content}");
        }
        assert!(
            parse_removal(
                &tags(&[&["e", &id], &["e", &id]]),
                r#"{"v":1,"action":"remove"}"#
            )
            .is_none()
        );
        assert!(!event_id_is_valid(&id.to_uppercase()));
    }
}
