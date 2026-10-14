//! Account relay-list handlers: NIP-65 (kind 10002) and the Marmot inbox list
//! (kind 10050).
//!
//! Both kinds are *replaceable*, so a control edit reads the published list,
//! overlays one entry and republishes the merge — the same read-merge-publish
//! contract `wn relays` applies from the CLI. A read the connector cannot
//! confirm is refused rather than published as a partial replacement, so one
//! edit can never drop the entries it did not name.

use std::sync::Arc;

use agent_control::{
    AgentControlRelayList, AgentControlRelayListDirection, AgentControlRelayListType,
    AgentControlRelayLists, AgentControlResponse,
};
use cgka_traits::TransportEndpoint;
use marmot_app::{AccountRelayListState, AccountRelayListStatus};

use crate::validation::{endpoint, normalize_hex, validate_relay_url};
use crate::{AgentConnector, ConnectorError};

/// One control-plane relay-list edit, resolved from the wire request.
pub(crate) struct RelayListEdit {
    pub(crate) account_id_hex: String,
    pub(crate) relay_type: AgentControlRelayListType,
    pub(crate) url: String,
    pub(crate) direction: AgentControlRelayListDirection,
    pub(crate) add: bool,
}

impl AgentConnector {
    /// Cached relay lists for one local account.
    ///
    /// This is a local read: it reports what the account published or last
    /// ingested, and never turns a relay outage into an empty list. An edit
    /// answers with the state it just published.
    pub(crate) fn relay_lists_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(&normalize_hex(account_id_hex)?)?;
        let status = self.app.account_relay_list_status(&account.label)?;
        Ok(AgentControlResponse::RelayLists {
            account_id_hex: account.account_id_hex,
            relay_lists: relay_lists_from_status(&status),
        })
    }

    /// Add or remove one relay in one published account relay list.
    pub(crate) async fn relay_list_edit_response(
        &self,
        edit: RelayListEdit,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(&normalize_hex(&edit.account_id_hex)?)?;
        let relay_type = edit.relay_type;
        // kind 10050 has no read/write roles. Refuse a named direction before
        // any network work instead of ignoring an argument the caller believed
        // applied.
        if relay_type == AgentControlRelayListType::Inbox
            && edit.direction != AgentControlRelayListDirection::Both
        {
            return Err(ConnectorError::InvalidRelayListEdit(
                "direction applies to nip65 only",
            ));
        }
        let url = validate_relay_url(&edit.url, self.allow_loopback_relays)?;
        // Serialize edits per account: two control requests that read the same
        // snapshot would otherwise each publish a merge of it, and the loser's
        // entry would vanish even though both answered success.
        let edit_lock = self.relay_list_edit_lock(&account.account_id_hex);
        let _edit_guard = edit_lock.lock().await;
        let cached = self.app.account_relay_list_status(&account.label)?;
        let source_relays = self.relay_list_source_relays(&cached);
        // The read is attempted even with an empty configured relay list: the
        // app falls back to the directory and default relays, so an empty
        // configuration is not "nothing to read" (the trap the profile publish
        // had to fix). A read that returns nothing is unconfirmed, not empty.
        self.app
            .fetch_current_account_relay_list_status_for_account_id(
                &account.account_id_hex,
                source_relays,
                Some(relay_type.as_str()),
            )
            .await?
            .ok_or(ConnectorError::RelayListInconclusive("read_empty"))?;
        // The fetch persists what it read through `merge_relay_list_status`,
        // which keeps the newer state per kind and keeps the cache on a tie, so
        // the cached status now holds the newer of the read and the cache: a
        // lagging relay cannot hand back a copy older than the local cache, and
        // one edit cannot republish the stale entries that read returned
        // (mdk#920). Re-reading it is that merged state.
        let merged = self.app.account_relay_list_status(&account.label)?;
        let current = relay_list_state_for(&merged, relay_type).clone();
        let next = apply_relay_edit(&current, relay_type, &url, edit.direction, edit.add)?;
        let route = self.relay_list_route(&cached, &next, &url, edit.add);
        let status = match relay_type {
            AgentControlRelayListType::Nip65 => {
                self.runtime
                    .publish_account_nip65_relay_set(
                        &account.label,
                        unique_endpoints(&next.read_relays),
                        unique_endpoints(&next.write_relays),
                        route,
                    )
                    .await?
            }
            AgentControlRelayListType::Inbox => {
                self.runtime
                    .publish_account_relay_list_kind(
                        &account.label,
                        relay_type.as_str(),
                        unique_endpoints(&next.relays),
                        route,
                    )
                    .await?
            }
        };
        Ok(AgentControlResponse::RelayLists {
            account_id_hex: account.account_id_hex,
            relay_lists: relay_lists_from_status(&status),
        })
    }

    /// Per-account edit lock serializing relay-list mutations.
    fn relay_list_edit_lock(&self, account_id_hex: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .relay_list_edits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks
            .entry(account_id_hex.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Relays a relay-list read starts from, mirroring `wn relays`: the
    /// connector's configured relays first (a re-bootstrap with new `--relay`
    /// values is exactly the case where the published list must be re-read and
    /// adopted), then the relays the account already remembers.
    fn relay_list_source_relays(&self, cached: &AccountRelayListStatus) -> Vec<TransportEndpoint> {
        let configured = self.configured_relay_endpoints();
        if !configured.is_empty() {
            return configured;
        }
        let mut remembered = cached.bootstrap_relays.clone();
        remembered.extend(cached.default_relays.clone());
        remembered.extend(cached.nip65.relays.clone());
        remembered.extend(cached.inbox.relays.clone());
        unique_endpoints(&remembered)
    }

    /// Route one relay-list publication goes through.
    ///
    /// An add always includes the edited URL: the relay being adopted is by
    /// definition not in the account's own NIP-65 write set yet, so the route
    /// derived from that set would leave it without the kind-10002 event that
    /// names it. The app unions this route with the account's own outbox, so the
    /// relays already in the list are republished to as well.
    fn relay_list_route(
        &self,
        cached: &AccountRelayListStatus,
        next: &AccountRelayListState,
        url: &str,
        add: bool,
    ) -> Vec<TransportEndpoint> {
        let mut route = cached.bootstrap_relays.clone();
        let configured = self.configured_relay_endpoints();
        if configured.is_empty() {
            route.extend(next.relays.clone());
            route.extend(next.read_relays.clone());
            route.extend(next.write_relays.clone());
        } else {
            route.extend(configured.into_iter().map(|endpoint| endpoint.0));
        }
        if add {
            route.push(url.to_owned());
        }
        unique_endpoints(&route)
    }
}

/// The cached or published state of one relay list kind.
fn relay_list_state_for(
    status: &AccountRelayListStatus,
    relay_type: AgentControlRelayListType,
) -> &AccountRelayListState {
    match relay_type {
        AgentControlRelayListType::Nip65 => &status.nip65,
        AgentControlRelayListType::Inbox => &status.inbox,
    }
}

/// NIP-65 read/write roles, falling back to the compatibility set when a record
/// predates directional roles (the rule `nip65_relay_roles` applies in the CLI).
fn nip65_relay_roles(state: &AccountRelayListState) -> (Vec<String>, Vec<String>) {
    if state.read_relays.is_empty() && state.write_relays.is_empty() {
        return (state.relays.clone(), state.relays.clone());
    }
    (state.read_relays.clone(), state.write_relays.clone())
}

/// Overlay one relay entry onto the list state, keeping every entry the edit did
/// not name.
///
/// Adding a direction an entry already has is a no-op; adding one it lacks
/// widens the entry, which is how an unmarked (read *and* write) NIP-65 entry is
/// expressed. Removing narrows it instead. An entry present in one direction
/// keeps its other direction either way.
fn apply_relay_edit(
    current: &AccountRelayListState,
    relay_type: AgentControlRelayListType,
    url: &str,
    direction: AgentControlRelayListDirection,
    add: bool,
) -> Result<AccountRelayListState, ConnectorError> {
    let mut next = current.clone();
    match relay_type {
        AgentControlRelayListType::Nip65 => {
            let (mut read_relays, mut write_relays) = nip65_relay_roles(current);
            match direction {
                AgentControlRelayListDirection::Read => update_relays(&mut read_relays, url, add),
                AgentControlRelayListDirection::Write => update_relays(&mut write_relays, url, add),
                AgentControlRelayListDirection::Both => {
                    update_relays(&mut read_relays, url, add);
                    update_relays(&mut write_relays, url, add);
                }
            }
            // A NIP-65 list with no write relay leaves the account unable to
            // publish anywhere, which is a worse outcome than a refused edit.
            if write_relays.is_empty() {
                return Err(ConnectorError::InvalidRelayListEdit(
                    "would leave the nip65 write set empty",
                ));
            }
            next.read_relays = read_relays;
            next.relays = write_relays.clone();
            next.write_relays = write_relays;
        }
        AgentControlRelayListType::Inbox => {
            let mut relays = current.relays.clone();
            update_relays(&mut relays, url, add);
            if relays.is_empty() {
                return Err(ConnectorError::InvalidRelayListEdit(
                    "would leave the inbox list empty",
                ));
            }
            next.relays = relays;
            next.read_relays = Vec::new();
            next.write_relays = Vec::new();
        }
    }
    Ok(next)
}

/// Comparison key for one relay entry.
///
/// Relay lists are ingested as trimmed raw tag text
/// (`parse_nip65_relay_set` / `relay_list_state_from_event`), so the same relay
/// can be published as `wss://relay.example` by one client and
/// `wss://relay.example/` by another. Comparing the text would treat those as
/// two entries: a removal would appear to succeed while the variant stayed in
/// the list and was republished, and an add could keep both. Compare the parsed
/// URL form instead, falling back to the trimmed text for an entry this device
/// cannot parse at all.
fn relay_entry_key(value: &str) -> String {
    let value = value.trim();
    match url::Url::parse(value) {
        Ok(parsed) => parsed.to_string(),
        Err(_) => value.to_owned(),
    }
}

/// Add or remove one URL, keeping the list sorted and deduplicated the way
/// `wn relays` does.
///
/// The published text stays exactly what the caller supplied (the same text
/// `wn relays` publishes); only the comparison is canonical. A removal drops
/// every textual variant of the relay it names, so the next read cannot hand a
/// variant back.
fn update_relays(relays: &mut Vec<String>, url: &str, add: bool) {
    let key = relay_entry_key(url);
    if add {
        if !relays.iter().any(|relay| relay_entry_key(relay) == key) {
            relays.push(url.to_owned());
        }
    } else {
        relays.retain(|relay| relay_entry_key(relay) != key);
    }
    relays.sort();
    relays.dedup();
}

fn unique_endpoints(values: &[String]) -> Vec<TransportEndpoint> {
    let mut unique: Vec<TransportEndpoint> = Vec::new();
    for value in values {
        let endpoint = endpoint(value);
        if !unique.contains(&endpoint) {
            unique.push(endpoint);
        }
    }
    unique
}

fn relay_list_from_state(state: &AccountRelayListState) -> AgentControlRelayList {
    AgentControlRelayList {
        relays: state.relays.clone(),
        read_relays: state.read_relays.clone(),
        write_relays: state.write_relays.clone(),
        created_at: state.created_at,
    }
}

fn relay_lists_from_status(status: &AccountRelayListStatus) -> AgentControlRelayLists {
    AgentControlRelayLists {
        nip65: relay_list_from_state(&status.nip65),
        inbox: relay_list_from_state(&status.inbox),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nip65_state(read: &[&str], write: &[&str]) -> AccountRelayListState {
        AccountRelayListState {
            kind: 10_002,
            created_at: 0,
            relays: write.iter().map(|relay| (*relay).to_owned()).collect(),
            read_relays: read.iter().map(|relay| (*relay).to_owned()).collect(),
            write_relays: write.iter().map(|relay| (*relay).to_owned()).collect(),
        }
    }

    fn inbox_state(relays: &[&str]) -> AccountRelayListState {
        AccountRelayListState {
            kind: 10_050,
            created_at: 0,
            relays: relays.iter().map(|relay| (*relay).to_owned()).collect(),
            read_relays: Vec::new(),
            write_relays: Vec::new(),
        }
    }

    #[test]
    fn nip65_add_keeps_unmodified_directional_entries() {
        let current = nip65_state(
            &["wss://both.example", "wss://read.example"],
            &["wss://both.example", "wss://write.example"],
        );

        let next = apply_relay_edit(
            &current,
            AgentControlRelayListType::Nip65,
            "wss://new.example",
            AgentControlRelayListDirection::Both,
            true,
        )
        .unwrap();

        assert_eq!(
            next.read_relays,
            vec![
                "wss://both.example",
                "wss://new.example",
                "wss://read.example"
            ]
        );
        assert_eq!(
            next.write_relays,
            vec![
                "wss://both.example",
                "wss://new.example",
                "wss://write.example"
            ]
        );
        assert_eq!(next.relays, next.write_relays);
    }

    #[test]
    fn nip65_directional_add_widens_only_that_direction() {
        let current = nip65_state(&["wss://read.example"], &["wss://write.example"]);

        let added_read = apply_relay_edit(
            &current,
            AgentControlRelayListType::Nip65,
            "wss://both.example",
            AgentControlRelayListDirection::Read,
            true,
        )
        .unwrap();
        assert_eq!(
            added_read.read_relays,
            vec!["wss://both.example", "wss://read.example"]
        );
        assert_eq!(added_read.write_relays, vec!["wss://write.example"]);

        let added_write = apply_relay_edit(
            &added_read,
            AgentControlRelayListType::Nip65,
            "wss://both.example",
            AgentControlRelayListDirection::Write,
            true,
        )
        .unwrap();
        assert_eq!(
            added_write.read_relays,
            vec!["wss://both.example", "wss://read.example"]
        );
        assert_eq!(
            added_write.write_relays,
            vec!["wss://both.example", "wss://write.example"]
        );
    }

    #[test]
    fn nip65_remove_narrows_only_the_named_direction() {
        let current = nip65_state(
            &["wss://both.example", "wss://read.example"],
            &["wss://both.example", "wss://write.example"],
        );

        let next = apply_relay_edit(
            &current,
            AgentControlRelayListType::Nip65,
            "wss://both.example",
            AgentControlRelayListDirection::Read,
            false,
        )
        .unwrap();

        assert_eq!(next.read_relays, vec!["wss://read.example"]);
        assert_eq!(
            next.write_relays,
            vec!["wss://both.example", "wss://write.example"]
        );
    }

    #[test]
    fn nip65_remove_refuses_to_empty_the_write_set() {
        let current = nip65_state(&["wss://both.example"], &["wss://both.example"]);

        let error = apply_relay_edit(
            &current,
            AgentControlRelayListType::Nip65,
            "wss://both.example",
            AgentControlRelayListDirection::Both,
            false,
        )
        .unwrap_err();

        assert!(matches!(error, ConnectorError::InvalidRelayListEdit(_)));
        // A read-only removal leaves a write route in place and is allowed.
        assert!(
            apply_relay_edit(
                &current,
                AgentControlRelayListType::Nip65,
                "wss://both.example",
                AgentControlRelayListDirection::Read,
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn legacy_nip65_state_without_roles_edits_both_sets() {
        let current = AccountRelayListState {
            kind: 10_002,
            created_at: 7,
            relays: vec!["wss://legacy.example".to_owned()],
            read_relays: Vec::new(),
            write_relays: Vec::new(),
        };

        let next = apply_relay_edit(
            &current,
            AgentControlRelayListType::Nip65,
            "wss://new.example",
            AgentControlRelayListDirection::Both,
            true,
        )
        .unwrap();

        assert_eq!(
            next.read_relays,
            vec!["wss://legacy.example", "wss://new.example"]
        );
        assert_eq!(next.write_relays, next.read_relays);
    }

    #[test]
    fn inbox_edit_replaces_only_the_named_entry() {
        let current = inbox_state(&["wss://old.example", "wss://other.example"]);

        let added = apply_relay_edit(
            &current,
            AgentControlRelayListType::Inbox,
            "wss://new.example",
            AgentControlRelayListDirection::Both,
            true,
        )
        .unwrap();
        assert_eq!(
            added.relays,
            vec![
                "wss://new.example",
                "wss://old.example",
                "wss://other.example"
            ]
        );
        assert!(added.read_relays.is_empty() && added.write_relays.is_empty());

        let removed = apply_relay_edit(
            &added,
            AgentControlRelayListType::Inbox,
            "wss://old.example",
            AgentControlRelayListDirection::Both,
            false,
        )
        .unwrap();
        assert_eq!(
            removed.relays,
            vec!["wss://new.example", "wss://other.example"]
        );

        let error = apply_relay_edit(
            &inbox_state(&["wss://only.example"]),
            AgentControlRelayListType::Inbox,
            "wss://only.example",
            AgentControlRelayListDirection::Both,
            false,
        )
        .unwrap_err();
        assert!(matches!(error, ConnectorError::InvalidRelayListEdit(_)));
    }

    #[test]
    fn relay_entry_keys_match_trailing_slash_and_case_variants() {
        assert_eq!(
            relay_entry_key("wss://relay.example"),
            relay_entry_key("wss://relay.example/")
        );
        assert_eq!(
            relay_entry_key("wss://relay.example"),
            relay_entry_key(" wss://Relay.Example ")
        );
        // An entry this device cannot parse still compares to itself, so a
        // malformed legacy entry is removable rather than permanent.
        assert_eq!(
            relay_entry_key("not-a-relay"),
            relay_entry_key(" not-a-relay ")
        );
        assert_ne!(
            relay_entry_key("not-a-relay"),
            relay_entry_key("wss://relay.example")
        );
    }

    #[test]
    fn relay_edits_match_a_stored_variant() {
        let current = AccountRelayListState {
            kind: 10_002,
            created_at: 1,
            relays: vec!["wss://relay.example/".to_owned()],
            read_relays: vec!["wss://relay.example/".to_owned()],
            write_relays: vec!["wss://relay.example/".to_owned()],
        };

        // Adding the slash-less form of an entry that is already present is a
        // no-op instead of a second entry.
        let added = apply_relay_edit(
            &current,
            AgentControlRelayListType::Nip65,
            "wss://relay.example",
            AgentControlRelayListDirection::Both,
            true,
        )
        .unwrap();
        assert_eq!(added.write_relays, vec!["wss://relay.example/"]);

        // Removing the slash-less form drops the stored variant.
        let removed = apply_relay_edit(
            &current,
            AgentControlRelayListType::Nip65,
            "wss://relay.example",
            AgentControlRelayListDirection::Read,
            false,
        )
        .unwrap();
        assert!(removed.read_relays.is_empty());
        assert_eq!(removed.write_relays, vec!["wss://relay.example/"]);
    }
}
