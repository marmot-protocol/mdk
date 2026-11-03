//! Shared Nostr reference decoder: one parse, one typed target, one bounded
//! error.
//!
//! mdk#2362 slice 2. Every surface that resolves a NIP-19 or hex reference —
//! the identity parser ([`crate::ids::account_id_hex_from_ref`]) and the
//! public-event preview parser — calls [`decode_reference`], so the accepted
//! families, the length budgets and the rejection reasons are decided in one
//! place. The Markdown recognizer is deliberately not a caller: it stays
//! shape-only (`marmot-markdown::nostr`), so a token it renders may still be
//! rejected here; that divergence is the identity-reference corpus's
//! documented baseline.
//!
//! The decoder never echoes its input: [`ReferenceDecodeError`] carries only
//! a bounded reason, and no message built from it names reference material.

use crate::error::DirectoryError;
use nostr::nips::nip01::Coordinate;
use nostr::nips::nip19::{FromBech32, Nip19, Nip19Profile};
use nostr::prelude::{EventId, Kind, RelayUrl};
use nostr_sdk::prelude::PublicKey;

/// The surface a reference arrives on. Gates which families decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceContext {
    /// Account-id resolution (`account_id_hex_from_ref`): accepts hex keys,
    /// `npub` and `nprofile` (bare or `nostr:`-wrapped). Every other family
    /// is [`ReferenceDecodeError::UnsupportedFamily`].
    Identity,
    /// Public-event preview resolution: accepts bare and `nostr:`-wrapped
    /// hex event ids, `note`, `nevent` and `naddr`. Identity families
    /// (`npub`, `nprofile`) are [`ReferenceDecodeError::UnsupportedFamily`].
    Event,
    /// Message-prose resolution: an explicit reference only — `npub`,
    /// `nprofile`, `note`, `nevent` or `naddr`, optionally `nostr:`-wrapped.
    /// Bare hex is ambiguous in prose (a bare 32 bytes is both an event id
    /// and a public key), so it is [`ReferenceDecodeError::Malformed`] here.
    /// No production caller uses this context yet; the PR3 binding will.
    #[allow(dead_code)]
    Prose,
}

/// The target a reference resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceTarget {
    /// A public key: the identity an `npub`/`nprofile` names.
    Identity(PublicKey),
    /// An event id: what a bare hex id, `note` or `nevent` names.
    Event(EventId),
    /// A `(kind, author, d)` coordinate: what an `naddr` names.
    Coordinate(Coordinate),
}

/// A decoded reference: its target plus the relay hints that traveled with it.
/// Hints are query inputs only; they never decide identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedReference {
    pub target: ReferenceTarget,
    pub relay_hints: Vec<RelayUrl>,
}

/// Bounded decode failure. Carries no input echo and no position data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceDecodeError {
    /// Empty input, a length over the context's budget, or a token that does
    /// not parse as any reference shape the context could accept.
    Malformed,
    /// A well-formed reference whose family this context does not accept.
    UnsupportedFamily,
    /// A secret-key reference (`nsec`). Never resolved on any context.
    SecretRejected,
}

/// Matches the currently locked Bech32/Bech32m code-length ceiling
/// (`bech32` 0.11.1), not a universal NIP-19 protocol limit.
pub(crate) const MAX_NPROFILE_REFERENCE_BYTES: usize = 1023;

/// Longest reference string the event and prose contexts accept; longer
/// input is [`ReferenceDecodeError::Malformed`].
pub(crate) const MAX_REFERENCE_BYTES: usize = 5_000;

/// Decode one reference for one context.
///
/// The result is context-gated, so callers match on [`DecodedReference::target`]
/// without re-checking family rules. Errors are bounded: see
/// [`ReferenceDecodeError`].
pub fn decode_reference(
    input: &str,
    context: ReferenceContext,
) -> Result<DecodedReference, ReferenceDecodeError> {
    match context {
        ReferenceContext::Identity => identity(input),
        ReferenceContext::Event => event(input),
        ReferenceContext::Prose => prose(input),
    }
}

/// NIP-01 replaceable rule: newer versions supersede, keyed by the
/// coordinate. rust-nostr also counts kind 41 here, which is not
/// replaceable by coordinate in NIP-01.
pub(crate) fn is_replaceable(kind: Kind) -> bool {
    let kind = kind.as_u16();
    kind == 0 || kind == 3 || (10_000..20_000).contains(&kind)
}

/// The narrow account-key parser: hex or `npub`, never a profile. The
/// 0.45 SDK parser also accepts `nprofile`, which this contract excludes.
pub(crate) fn parse_account_key(value: &str) -> Result<PublicKey, DirectoryError> {
    if value.starts_with("nprofile1") || value.starts_with("nostr:nprofile1") {
        return Err(DirectoryError::InvalidPublicKey);
    }
    PublicKey::parse(value).map_err(|_| DirectoryError::InvalidPublicKey)
}

/// The identity-context nprofile fallback token: strip one lowercase
/// `nostr:` prefix, then bound the complete encoded token at
/// [`MAX_NPROFILE_REFERENCE_BYTES`] (the prefix is excluded from the
/// budget).
pub(crate) fn nprofile_fallback_token(reference: &str) -> Result<&str, ReferenceDecodeError> {
    let profile_ref = reference.strip_prefix("nostr:").unwrap_or(reference);
    if profile_ref.len() > MAX_NPROFILE_REFERENCE_BYTES {
        return Err(ReferenceDecodeError::Malformed);
    }
    Ok(profile_ref)
}

/// Identity context: hex key, `npub`, or the `nprofile` fallback that
/// discards relay hints and keeps the first type-0 key.
fn identity(reference: &str) -> Result<DecodedReference, ReferenceDecodeError> {
    if let Ok(key) = parse_account_key(reference) {
        return Ok(DecodedReference {
            target: ReferenceTarget::Identity(key),
            relay_hints: Vec::new(),
        });
    }
    let profile_ref = nprofile_fallback_token(reference)?;
    match Nip19Profile::from_bech32(profile_ref) {
        Ok(profile) => Ok(DecodedReference {
            target: ReferenceTarget::Identity(profile.public_key),
            relay_hints: Vec::new(),
        }),
        // An nprofile-shaped token that fails TLV or checksum decoding, and
        // every other family the fallback reached, is malformed for identity.
        Err(_) => Err(ReferenceDecodeError::Malformed),
    }
}

/// Event context: bare or `nostr:`-wrapped hex event id, `note`, `nevent`
/// or `naddr` with the preview's coordinate admission rule.
fn event(raw: &str) -> Result<DecodedReference, ReferenceDecodeError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_REFERENCE_BYTES {
        return Err(ReferenceDecodeError::Malformed);
    }
    event_or_prose_token(trimmed.strip_prefix("nostr:").unwrap_or(trimmed))
}

/// Prose context: an explicit family reference only, never bare hex. The
/// union of the identity and event families; a bare 32 bytes is ambiguous
/// in prose (it is both a public key and an event id), so it stays
/// [`ReferenceDecodeError::Malformed`].
fn prose(raw: &str) -> Result<DecodedReference, ReferenceDecodeError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_REFERENCE_BYTES {
        return Err(ReferenceDecodeError::Malformed);
    }
    let token = trimmed.strip_prefix("nostr:").unwrap_or(trimmed);
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ReferenceDecodeError::Malformed);
    }
    // Both stages see the same input; identity reads npub/nprofile, event
    // reads note/nevent/naddr. A secret rejection outranks a family gap,
    // which outranks a shape failure, so the reason names the sharpest
    // finding either stage made.
    match (identity(trimmed), event(trimmed)) {
        (Ok(decoded), _) | (_, Ok(decoded)) => Ok(decoded),
        (Err(left), Err(right)) => Err(worst_reason(left, right)),
    }
}

/// The reason a caller should see first: secrets over family gaps over
/// shape failures.
fn worst_reason(left: ReferenceDecodeError, right: ReferenceDecodeError) -> ReferenceDecodeError {
    use ReferenceDecodeError::{Malformed, SecretRejected, UnsupportedFamily};
    match (left, right) {
        (SecretRejected, _) | (_, SecretRejected) => SecretRejected,
        (UnsupportedFamily, _) | (_, UnsupportedFamily) => UnsupportedFamily,
        _ => Malformed,
    }
}

/// The shared bech32 stage behind [`event`] and [`prose`].
fn event_or_prose_token(token: &str) -> Result<DecodedReference, ReferenceDecodeError> {
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        let id = EventId::from_hex(token).map_err(|_| ReferenceDecodeError::Malformed)?;
        return Ok(DecodedReference {
            target: ReferenceTarget::Event(id),
            relay_hints: Vec::new(),
        });
    }
    match Nip19::from_bech32(token) {
        Ok(Nip19::EventId(id)) => Ok(DecodedReference {
            target: ReferenceTarget::Event(id),
            relay_hints: Vec::new(),
        }),
        Ok(Nip19::Event(event)) => Ok(DecodedReference {
            target: ReferenceTarget::Event(event.event_id),
            relay_hints: event.relays,
        }),
        Ok(Nip19::Coordinate(naddr)) => {
            let kind = naddr.coordinate.kind;
            let supported = kind.is_addressable()
                || (is_replaceable(kind) && naddr.coordinate.identifier.is_empty());
            if supported {
                Ok(DecodedReference {
                    target: ReferenceTarget::Coordinate(naddr.coordinate),
                    relay_hints: naddr.relays,
                })
            } else {
                Err(ReferenceDecodeError::UnsupportedFamily)
            }
        }
        // npub/nprofile are identity families; naddr kinds the preview rule
        // does not admit; nrelay is a relay hint, not a reference target.
        Ok(Nip19::Pubkey(_)) | Ok(Nip19::Profile(_)) => {
            Err(ReferenceDecodeError::UnsupportedFamily)
        }
        // A valid checksum over a secret is still a secret: never resolved,
        // and reported as its own reason so callers cannot mistake it for a
        // shape failure.
        Ok(Nip19::Secret(_)) => Err(ReferenceDecodeError::SecretRejected),
        // Everything else — bech32 0.11.1 has no nrelay variant, so every
        // nrelay token fails prefix classification and lands here; any
        // optional SDK-only secret form is not a resolvable reference either.
        Ok(_) => Err(ReferenceDecodeError::UnsupportedFamily),
        Err(_) => Err(ReferenceDecodeError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_NPROFILE_REFERENCE_BYTES, ReferenceContext, ReferenceDecodeError, ReferenceTarget,
        decode_reference, nprofile_fallback_token,
    };
    use crate::error::DirectoryError;
    use crate::ids::parse_account_id_hex;

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../marmot-app/tests/support/identity_reference_vectors.rs"
    ));

    fn decoded(
        reference: &str,
        context: ReferenceContext,
    ) -> Result<ReferenceTarget, ReferenceDecodeError> {
        decode_reference(reference, context).map(|decoded| decoded.target)
    }

    #[test]
    fn identity_context_matches_the_shared_corpus() {
        for case in cases() {
            let Some(expected_hex) = case.app_account_id_hex else {
                continue;
            };
            assert_eq!(
                decoded(&case.reference, ReferenceContext::Identity)
                    .unwrap_or_else(|_| panic!("case {} should decode", case.name)),
                ReferenceTarget::Identity(
                    crate::reference::parse_account_key(expected_hex).unwrap()
                ),
                "case {}",
                case.name
            );
        }
    }

    #[test]
    fn event_context_matches_the_shared_corpus() {
        for case in cases() {
            let expected = match case.previews_target {
                Some(key) if key.starts_with("event:") => ReferenceTarget::Event(
                    nostr::prelude::EventId::from_hex(&key["event:".len()..]).unwrap(),
                ),
                // Coordinate keys are asserted by the preview parser's own
                // corpus test, which reads the same cache_key the decoder
                // feeds; here the coordinate rows only assert acceptance.
                Some(key) if key.starts_with("coordinate:") => {
                    assert!(
                        matches!(
                            decoded(&case.reference, ReferenceContext::Event),
                            Ok(ReferenceTarget::Coordinate(_))
                        ),
                        "case {} should decode to a coordinate",
                        case.name
                    );
                    continue;
                }
                _ => continue,
            };
            assert_eq!(
                decoded(&case.reference, ReferenceContext::Event)
                    .unwrap_or_else(|_| panic!("case {} should decode", case.name)),
                expected,
                "case {}",
                case.name
            );
        }
    }

    #[test]
    fn every_context_rejects_the_secret_row() {
        for case in cases() {
            if case.name != "nsec_synthetic" {
                continue;
            }
            // The identity context speaks only hex/npub/nprofile, so the
            // nsec token never reaches the Nip19 enum and is malformed
            // there; the event and prose contexts decode far enough to
            // name the secret.
            assert_eq!(
                decoded(&case.reference, ReferenceContext::Identity),
                Err(ReferenceDecodeError::Malformed),
                "case {} must never decode",
                case.name
            );
            for context in [ReferenceContext::Event, ReferenceContext::Prose] {
                assert_eq!(
                    decoded(&case.reference, context),
                    Err(ReferenceDecodeError::SecretRejected),
                    "case {} must never decode",
                    case.name
                );
            }
        }
    }

    /// The nrelay differing row, decided from runs: markdown classifies the
    /// HRP (shape-only), while every decoder context reports a bounded
    /// rejection. `Nip19::from_bech32` has no nrelay variant, so the token
    /// never reaches family logic; the bounded error is the decoder's
    /// target behavior, not a change from today's parsers.
    #[test]
    fn nrelay_is_never_a_reference_target() {
        for context in [
            ReferenceContext::Identity,
            ReferenceContext::Event,
            ReferenceContext::Prose,
        ] {
            assert_eq!(
                decoded(NRELAY_EXAMPLE, context),
                Err(ReferenceDecodeError::Malformed),
                "nrelay under {context:?} must not decode"
            );
            assert_eq!(
                decoded(&format!("nostr:{NRELAY_EXAMPLE}"), context),
                Err(ReferenceDecodeError::Malformed),
                "nostr-wrapped nrelay under {context:?} must not decode"
            );
        }
    }

    #[test]
    fn prose_context_rejects_bare_hex_and_accepts_explicit_families() {
        assert_eq!(
            decoded(EVENT_ID_32_HEX, ReferenceContext::Prose),
            Err(ReferenceDecodeError::Malformed)
        );
        assert_eq!(
            decoded(ACCOUNT_ID, ReferenceContext::Prose),
            Err(ReferenceDecodeError::Malformed)
        );
        assert!(matches!(
            decoded(NPUB, ReferenceContext::Prose),
            Ok(ReferenceTarget::Identity(_))
        ));
        assert!(matches!(
            decoded(NOTE_EVENT_HRP, ReferenceContext::Prose),
            Ok(ReferenceTarget::Event(_))
        ));
        assert!(matches!(
            decoded(&format!("nostr:{NPUB}"), ReferenceContext::Prose),
            Ok(ReferenceTarget::Identity(_))
        ));
    }

    #[test]
    fn identity_context_still_rejects_every_non_identity_family() {
        assert_eq!(
            decoded(NOTE_EVENT_HRP, ReferenceContext::Identity),
            Err(ReferenceDecodeError::Malformed)
        );
        // Bare hex is an identity family: the same 32 bytes an event context
        // reads as an event id, the identity context reads as a public key.
        assert!(matches!(
            decoded(EVENT_ID_32_HEX, ReferenceContext::Identity),
            Ok(ReferenceTarget::Identity(_))
        ));
    }

    #[test]
    fn nprofile_fallback_token_rejects_oversized_tokens_before_sdk_decode() {
        let accepted = "q".repeat(MAX_NPROFILE_REFERENCE_BYTES);
        assert_eq!(
            nprofile_fallback_token(&accepted).expect("1023-byte token stays eligible"),
            accepted.as_str()
        );
        let wrapped = format!("nostr:{accepted}");
        assert_eq!(
            nprofile_fallback_token(&wrapped).expect("prefix is excluded from the budget"),
            accepted.as_str()
        );

        let oversized = "q".repeat(MAX_NPROFILE_REFERENCE_BYTES + 1);
        assert_eq!(
            nprofile_fallback_token(&oversized),
            Err(ReferenceDecodeError::Malformed),
            "1024-byte token must not reach Nip19Profile::from_bech32"
        );
        assert_eq!(
            nprofile_fallback_token(&format!("nostr:{oversized}")),
            Err(ReferenceDecodeError::Malformed),
            "prefixed oversized token must not reach Nip19Profile::from_bech32"
        );
    }

    #[test]
    fn bounded_errors_do_not_leak_into_the_directory_boundary() {
        // The identity caller maps every decoder failure to the same
        // `DirectoryError::InvalidPublicKey` the pre-decoder parser returned,
        // so the public contract is unchanged by the shared decoder.
        for reason in [
            ReferenceDecodeError::Malformed,
            ReferenceDecodeError::UnsupportedFamily,
            ReferenceDecodeError::SecretRejected,
        ] {
            let failing = match reason {
                ReferenceDecodeError::Malformed => "not-a-reference",
                ReferenceDecodeError::UnsupportedFamily => NOTE_EVENT_HRP,
                ReferenceDecodeError::SecretRejected => NSEC_SYNTHETIC_REJECTION,
            };
            assert!(
                matches!(
                    crate::ids::account_id_hex_from_ref(failing),
                    Err(DirectoryError::InvalidPublicKey)
                ),
                "{reason:?} maps to InvalidPublicKey at the identity boundary"
            );
        }
        assert_eq!(parse_account_id_hex(ACCOUNT_ID).unwrap(), ACCOUNT_ID);
    }
}
