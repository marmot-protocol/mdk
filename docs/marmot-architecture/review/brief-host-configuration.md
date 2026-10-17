---
title: "Brief — Host-Supplied Deployment Configuration"
created: 2026-10-17
updated: 2026-10-17
tags: [marmot, architecture, review, brief, configuration, bindings]
status: proposed, needs approval before implementation
---

# Brief — Host-Supplied Deployment Configuration

The product-owner decision in [core structure §6](core-structure.md#6-product-owner-decisions) (item 5): White Noise's
deployment defaults move into configuration that hosts pass in, and `MarmotAppConfig::default()` becomes neutral. This
brief says which values that covers, what replaces each one, and the order of the change. `path:line` citations are
at `639abe576` (master after #2399). Following the [review's evidence rules](README.md#evidence-rules), statements are
observed in source unless marked (hypothesis).

## Why now

MDK is meant to serve any Marmot client ([§2.9](core-structure.md#29-generic-sdk-or-white-noises-app-core)). Today a
host that builds on the bindings and changes nothing:

- certifies recovery only against White Noise's two relays;
- onboards against five public indexers;
- creates every group with three third-party Blossom servers signed into its state;
- uploads profile images to primal;
- searches the directory through Vertex;
- stores secrets under the keychain service `com.marmot.whitenoise`;
- labels moderation reports `chat.whitenoise.report`;
- prefers KeyPackages tagged `whitenoise`.

Most of these can't be changed from Swift, Kotlin or C at all. Step 2 is done, so this brief is next in the plan
(#2360).

## What is compiled in today

| Value | Where | How it reaches runtime | Host override today |
| --- | --- | --- | --- |
| Recovery-operated relays (`relay.eu/us.whitenoise.chat`) | `marmot-app/src/config.rs:16-21` | `MarmotAppConfig::recovery_operated_relays`, default `:283-286`; read by `transport_nostr::recovery_required_endpoints` (`client/recovery.rs:751,1388,1434`) | Rust field only |
| Discovery indexers (purplepag.es, Vertex, nos.lol, ditto, primal) | `runtime/mod.rs:8878-8892` | Onboarding internals (`runtime/onboarding.rs:1748,1872,2398`) and UniFFI account setup (`marmot-uniffi/src/commands/account.rs:780`) | Per call in Rust; FFI only via `set_onboarding_discovery_relays` |
| Encrypted-media servers for new groups (divine.video, ditto, hzrd149) | `media/mod.rs:200-204` | Fallback when `service_endpoints.encrypted_media_blob_endpoints` is empty (`client/mod.rs:6601-6617`), then signed into the group's component | Rust `with_service_endpoints`; empty cannot mean none. Per group afterwards: `replace_encrypted_media_blob_endpoints` |
| Group-image server (the first of those three) | `media/mod.rs:208` | Upload and fetch with `server = None` (`media/group_image.rs:243,277`) | None in production |
| Profile-image server (primal) | `media/mod.rs:211` | `MarmotServiceEndpoints::compiled()` (`config.rs:522`); `None` still falls back to primal (`media/mod.rs:292`) | Rust `with_service_endpoints`; FFI per upload |
| Open Ranking search and profile relay (Vertex) | `config.rs:13-15` | `compiled()` (`config.rs:525-526`), read in `directory/search.rs:307-317,546-558` | Rust `with_open_ranking_provider` |
| Keychain service name `com.marmot.whitenoise` | `marmot-account/src/home.rs:31` | `AccountHome::open_with_default_keychain`, which UniFFI `Marmot::open` uses whenever the host gives no `SecretStore` (`marmot-uniffi/src/lib.rs:486-490`) | Rust and CLI; FFI only by supplying a whole `SecretStore` |
| Moderation label namespace `chat.whitenoise.report` | `moderation_reports.rs:33` | NIP-32 `L`/`l` tags on every report (`moderation_reports.rs:826,830`) | None |
| KeyPackage client preference (`whitenoise` first, `amethyst` last) | `key_package_records.rs:264-289` | Every KeyPackage selection (`:374`) | None |

`MarmotServiceEndpoints`' derived `Default` is already neutral. `compiled()`, which `MarmotAppConfig::default()`
uses (`config.rs:287`), is what adds the third-party services. `directory_relay_urls`,
`directory_search_fallback_seeds`, `moderation_report_config` and `key_package_client_name` already default to empty
or `None`.

## Two kinds of value

Most of these are deployment choices: a host can pick any value and talk to every other client. Four are not, and
each needs its own rule.

- **The group-image server decides where every member looks.** Group state stores the image's key and hash but no
  server. Upload and fetch both use the build's server (`group_image.rs:243,277`), so two clients built with different
  values can't see each other's group avatars. That stays true whatever this brief does.
- **Encrypted-media servers are signed into a group at creation.** A neutral default needs a defined meaning for "no
  servers", because today an empty list falls back to the built-in three.
- **The moderation namespace has an external reader.** The operator's report parser matches it
  (`docs/marmot-architecture/moderation-reports.md:86`).
- **The recovery-operated set feeds a route-policy hash.** `client/recovery.rs:1019-1028` hashes the sorted raw
  strings, so any change to the set, including an empty one, rebuilds every pending recovery scope once. Behaviour is
  otherwise safe: a route with no operated relay requires all its admitted relays (`transport-nostr/src/safety.rs:282-288`).
  So an empty set changes nothing for a host whose routes don't include White Noise's relays.

## Decision: one deployment record, an opt-in White Noise preset

Add `MarmotDeployment` to `marmot-app`, carried as `MarmotAppConfig::deployment`, and delete the scattered constants.

```rust
pub struct MarmotDeployment {
    pub recovery_operated_relays: Vec<String>,
    pub discovery_indexer_relays: Vec<String>,
    pub new_group_media_endpoints: Vec<String>,
    pub group_image_endpoint: Option<String>,
    pub profile_image_endpoint: Option<String>,
    pub open_ranking: Option<OpenRankingProvider>, // search endpoint + profile relays
    pub key_package_client_preference: KeyPackageClientPreference,
    pub keychain_service: String,
}
impl MarmotDeployment {
    pub fn neutral() -> Self { /* every list empty, every option None, keychain "org.marmot-protocol.mdk" */ }
    pub fn white_noise() -> Self { /* today's values, byte for byte */ }
}
```

- **`neutral()` means "this host hasn't configured that service".**
  - Recovery requires every admitted relay.
  - Onboarding searches only the account's own relays.
  - New groups are created without an encrypted-media component, and sending media fails with a clear error until the
    host sets servers.
  - Group and profile images can't be uploaded or fetched.
  - Directory search uses the relays it already has.
  - KeyPackage selection has no client preference.
- **`white_noise()` keeps today's behaviour exactly.** Its strings match the current constants, so the route-policy
  hash doesn't change and no recovery scope rebuilds. The White Noise apps, the CLI and `wn-agent` (both
  White Noise-branded hosts) opt into it explicitly. The installers, Docker and packaging files keep their own relay
  lists, which already match.
- **The moderation namespace moves into `ModerationReportConfig`**, next to the recipient and relays it already
  carries (`moderation_reports.rs:50-57`). It is per-deployment and `None` by default, so it needs no neutral value.
  The White Noise preset sets it in the config the apps already pass.
- **The keychain service name lives in the deployment record**, so the bindings can set it without supplying a whole
  `SecretStore`. Rust's `AccountHome::open_with_keychain` already takes a name.
- **One copy of each value.** The Vertex relay is defined twice today (`config.rs:15`, `runtime/mod.rs:8878`), and the
  White Noise relay list four times (`config.rs`, `agent-connector/src/bootstrap.rs:21-24`, `Justfile:138`, the
  installers). In Rust the preset becomes the one source, and the agent reads it.

The preset stays in MDK because the CLI, `wn-agent` and the bindings all need the same values. A White Noise app
gets them by asking for the preset, never by default.

## Binding surface

- UniFFI gets a `MarmotDeploymentFfi` record and two exported constructors: `marmot_deployment_white_noise()` and
  `marmot_deployment_neutral()`. `MarmotOptions` gets a `deployment` field, and the C ABI mirrors both.
  `marmot_open` takes the keychain service from the record whenever no `SecretStore` is given.
- A default is the risky case. If the White Noise apps picked up a neutral keychain name on upgrade, every existing
  install would lose its account secrets. So, once the flip lands, `deployment` has no binding default and becomes a
  required field. A host that hasn't chosen gets a build error, not orphaned secrets at runtime.
- `just binding-docs-gate` checks only callables, not records or defaults (`scripts/check_binding_docs.py`). The
  binding READMEs ("Runtime options", "Service endpoint defaults", `marmot-uniffi/README.md:241-358`) are rewritten
  by hand. Their claim that a `None` profile-image server disables uploads becomes true once the primal fallback goes.

## PR sequence

Each PR is green on its own. PRs 1 and 2 change no default behaviour.

1. **Add `MarmotDeployment` and route every consumer through it.** `MarmotAppConfig::default()` still uses
   `white_noise()`.
   - Move the onboarding indexers, the group- and profile-image servers, new-group media servers, Open Ranking and
     the KeyPackage preference from constants to the record.
   - Move the moderation namespace into `ModerationReportConfig`.
   - Delete the constants.
   - `MarmotServiceEndpoints` keeps only the collector routes (analytics, telemetry, audit), which step 6 owns.
   - `MarmotAppConfig` gains a field, which breaks struct literals, so this PR adds a CHANGELOG entry.
2. **Bindings and hosts.**
   - Add the UniFFI record and constructors, `MarmotOptions.deployment` (optional for now, defaulting to White
     Noise), and the C mirror.
   - The keychain name goes through the record.
   - The CLI and `wn-agent` call `MarmotDeployment::white_noise()` explicitly, and the agent's relay list reads it.
   - The simulator and tests choose explicitly. Most tests want `neutral()`; tests of White Noise behaviour use the
     preset.
3. **The flip, in a minor release.**
   - `MarmotAppConfig::default()` returns `neutral()`.
   - The binding `deployment` field becomes required.
   - The neutral "no servers" behaviour lands: no encrypted-media component on new groups, no profile-image fallback.
   - The release and integration notes list it as a required change, with the one-line White Noise migration
     (`deployment: marmot_deployment_white_noise()`). That follows `release.md#release-documentation`.

## Proof that behaviour is unchanged for White Noise

- A test pins `MarmotDeployment::white_noise()` to the values the deleted constants held. It also pins that the
  route-policy hash for a fixed route is the same before and after PR 1.
- PRs 1 and 2: the existing suites pass unchanged (`cargo nextest run -p marmot-app`, `-p marmot-uniffi`, `-p wn-cli`
  with `test-policy-overrides`, `just simulator-smoke`). The tests that assert today's values
  (`media/tests.rs:1352-1361`, `runtime/tests.rs:717-729`, `config.rs:992-1018`, `moderation_reports/tests.rs:315-319`,
  `src/tests/key_package_selection.rs`) move to assert the preset.
- PR 3: new tests for each neutral meaning:
  - recovery requires all admitted relays;
  - onboarding without indexers completes;
  - a group created without media servers has no encrypted-media component, and a media send says why;
  - the profile-image upload refuses.
  - The `marmot-uniffi` smoke tests open with each preset.

## Risks

| Risk | Mitigation |
| --- | --- |
| White Noise apps upgrade without choosing the preset and lose keychain secrets | The binding field is required after the flip, so the host fails to build instead |
| A host passes the White Noise relays spelled differently and rebuilds every recovery scope | The preset is the one source; the hash input stays the raw sorted strings, as today |
| Hosts that share groups disagree on the group-image server | Unchanged from today: a client built with another value already disagrees. Recording the server in group state (out of scope below) removes it |
| A group created without an encrypted-media component can't get one later | PR 3 first checks that `replace_encrypted_media_blob_endpoints` can add the component to a group that lacks it; if it can't, neutral new groups fail media setup with a clear error instead |
| The ~150 test sites using `MarmotAppConfig::default()` change meaning in PR 3 | PR 2 makes every test choose a preset explicitly before the default flips |

## Out of scope

- **Collector endpoints and product analytics.** The routes `marmotkit-endpoints.env` compiles into MarmotKit, the
  Aptabase delivery and its disclosure text all belong to step 6 (`marmot-observability`). Changing the compiled
  OTLP origin also changes the usage-diagnostics consent scope (`product_analytics/mod.rs:592-600`).
- **Putting the group-image server into group state.** That is a component change in the spec, so it goes to
  `marmot-protocol/marmot` after the review.
- **The CLI's and `wn-agent`'s own branding.** Home directory, socket names, "White Noise" strings and the QUIC
  broker default stay: those binaries are White Noise hosts.
- **The `whitenoise://` app-link schemes in `marmot-markdown`.** They are display classification. Making app-link
  schemes host-supplied is a separate, small change.
- **Retiring single-KeyPackage selection** (mdk#1696). This brief only moves its preference into configuration.

## Done when

- `MarmotAppConfig::default()` and the binding constructors name no White Noise or third-party service.
- Every White Noise value is defined once, in `MarmotDeployment::white_noise()`.
- The White Noise apps, the CLI and `wn-agent` pass that preset explicitly, with the same behaviour as before.
- The binding READMEs and the integration notes for the release say all of the above.

## Decisions for the product owner

1. **An opt-in White Noise preset inside MDK** (recommended), or no preset, with the White Noise apps holding the
   values themselves. Without one, the CLI and `wn-agent` would need their own copy.
2. **The neutral keychain service name.** The proposal is `org.marmot-protocol.mdk`. It matters only for hosts that
   never set one, because with a required binding field the White Noise apps always do.
3. **No media servers configured means new groups have no encrypted-media component** (recommended), or group
   creation fails until the host sets servers.
4. **The required binding field after the flip** (recommended, because of the keychain risk), or an optional field
   that defaults to neutral.
