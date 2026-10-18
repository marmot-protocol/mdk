---
title: "Brief — Host-Supplied Deployment Configuration"
created: 2026-10-17
updated: 2026-10-18
tags: [marmot, architecture, review, brief, configuration, bindings]
status: approved 2026-10-18, in implementation
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
| Discovery indexers (purplepag.es, Vertex, nos.lol, ditto, primal) | `runtime/mod.rs:8878-8892` | Onboarding appends them to the host's discovery relays and any discovered relay list (`runtime/onboarding.rs:1748,1872,1882-1911,2398`); UniFFI account setup passes them as the discovery set (`marmot-uniffi/src/commands/account.rs:130`, nine more, via `:780`) | Rust per call. FFI onboarding takes extra `discovery_relays` (`conversions/onboarding.rs:420`, `set_onboarding_discovery_relays`); FFI account setup can't change them |
| Encrypted-media servers for new groups (divine.video, ditto, hzrd149) | `media/mod.rs:200-204` | Fallback when `service_endpoints.encrypted_media_blob_endpoints` is empty (`client/mod.rs:6601-6617`), then signed into the group's component | Build time: `MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS` (`config.rs:11-12,519-521`), which three READMEs document. Runtime: Rust `with_service_endpoints`. Empty can't mean none. Per group afterwards: `replace_encrypted_media_blob_endpoints` |
| Group-image server (the first of those three) | `media/mod.rs:208` | Upload and fetch with `server = None` (`media/group_image.rs:243,277`) | None in production |
| Profile-image server (primal) | `media/mod.rs:211` | `MarmotServiceEndpoints::compiled()` (`config.rs:522`); `None` still falls back to primal (`media/mod.rs:292`) | Rust `with_service_endpoints`; FFI per upload |
| Open Ranking search and profile relay (Vertex) | `config.rs:13-15` | `compiled()` (`config.rs:525-526`), read in `directory/search.rs:307-317,546-558` | Rust `with_open_ranking_provider` |
| Keychain service name `com.marmot.whitenoise` | `marmot-account/src/home.rs:31` | `AccountHome::open_with_default_keychain`, which UniFFI `Marmot::open` uses whenever the host gives no `SecretStore` (`marmot-uniffi/src/lib.rs:486-490`) | Rust and CLI; FFI only by supplying a whole `SecretStore` |
| Moderation label namespace `chat.whitenoise.report` | `moderation_reports.rs:33` | NIP-32 `L`/`l` tags on every report (`moderation_reports.rs:826,830`) | None |
| KeyPackage client preference (`whitenoise` first, `amethyst` last) | `key_package_records.rs:264-289` | Every KeyPackage selection (`:374`) | None |

`MarmotServiceEndpoints`' derived `Default` is already neutral. `compiled()`, which `MarmotAppConfig::default()`
uses (`config.rs:287`), adds the profile-image server and Open Ranking. It leaves the new-group media list empty unless
the build set it, and the fallback in `client/mod.rs:6601-6617` adds the three servers. `directory_relay_urls`,
`directory_search_fallback_seeds`, `moderation_report_config` and `key_package_client_name` already default to empty
or `None`.

## Two kinds of value

Most of these are deployment choices: a host can pick any value and talk to every other client. Four are not, and
each needs its own rule.

- **The group-image server decides where every member looks.** Group state stores the image's key and hash but no
  server. Upload and fetch both use the build's server (`group_image.rs:243,277`), so two clients built with different
  values can't see each other's group avatars. That stays true whatever this brief does.
- **Encrypted-media servers are signed into a group at creation.** A neutral default needs a defined meaning for "no
  servers", because today an empty list falls back to the built-in three. A group created without the component can't
  gain one later through `replace_encrypted_media_blob_endpoints`, which refuses a group that doesn't require
  encrypted media (`groups.rs:1789-1793`, called at `client/mod.rs:3989`).
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
    pub moderation_label_namespace: Option<String>,
    pub keychain_service: String,
}
impl MarmotDeployment {
    pub fn neutral() -> Self { /* every list empty, every option None, keychain "org.marmot-protocol.mdk" */ }
    pub fn white_noise() -> Self { /* today's values, byte for byte */ }
}
```

- **`neutral()` means "this host hasn't configured that service".**
  - Recovery requires every admitted relay.
  - Onboarding has no compiled indexers. It still searches the discovery relays the host passes and any relay list it
    discovers for the account.
  - New groups follow decision 3 below: created without an encrypted-media component, so they stay text-only, or
    refused until the host sets servers.
  - Group images can't be uploaded or fetched, because group state holds no server.
  - Profile images have no default upload server. Peers' avatars still load from the signed `picture` URL in their
    profile (`media/avatar.rs:46-49`, `media/mod.rs:326-330`), which never used the endpoint.
  - Directory search uses the relays it already has, with no Open Ranking tier.
  - KeyPackage selection has no client preference.
  - Moderation reporting refuses a report destination while the namespace is unset, rather than publishing reports
    with no `L`/`l` label.
- **`white_noise()` keeps today's behaviour exactly.** Its strings match the current constants, so the route-policy
  hash doesn't change and no recovery scope rebuilds. The White Noise apps, the CLI and `wn-agent` (both
  White Noise-branded hosts) opt into it explicitly. The installers, Docker and packaging files keep their own relay
  lists, which already match.
- **The moderation namespace is a deployment field**, so the White Noise preset carries `chat.whitenoise.report` and
  the one-line migration sets it. Report staging reads it from the deployment instead of the constant
  (`moderation_reports.rs:33,826,830`). The destination stays in `ModerationReportConfig`, as now.
- **The keychain service name lives in the deployment record**, so the bindings can set it without supplying a whole
  `SecretStore`. Rust's `AccountHome::open_with_keychain` already takes a name.
- **One copy of each value, kept in its own role.** The Vertex URL is two roles today, the Open Ranking profile
  relay (`config.rs:15`) and a discovery indexer (`runtime/mod.rs:8878`). Both fields stay, and `white_noise()` sets
  them from one string. White Noise's two relays are also two roles. One is the recovery set (`config.rs:18-21`). The
  other is the messaging relays a new account publishes: the agent's bootstrap list
  (`agent-connector/src/bootstrap.rs:21-24`), `tui-prod` (`Justfile:138`) and the installers' `MARMOT_RELAYS`. The
  URLs match today, but changing who certifies history must not move where the agent publishes. So the messaging list
  keeps its own named constant in the agent, and the installers stay matching copies of it.

The preset stays in MDK because the CLI, `wn-agent` and the bindings all need the same values. A White Noise app
gets them by asking for the preset, never by default.

## Binding surface

- UniFFI gets a `MarmotDeploymentFfi` record and two exported constructors: `marmot_deployment_white_noise()` and
  `marmot_deployment_neutral()`. `MarmotOptions` gets a `deployment` field, and the C ABI mirrors both.
  `Marmot::open` takes the keychain service from the record whenever no `SecretStore` is given
  (`marmot-uniffi/src/lib.rs:486-490`).
- A default is the risky case. If the White Noise apps picked up a neutral keychain name on upgrade, every existing
  install would lose its account secrets. A required `MarmotOptions` field alone doesn't prevent that, because most
  constructors build `MarmotOptions` inside the binding:
  - UniFFI: `new`, `new_with_options`, `new_with_secret_store`, `new_with_cursor_persistence`, `new_with_client_name`
    and `new_with_configuration` (`marmot-uniffi/src/lib.rs:256-383`).
  - C: the matching `marmot_client_new*` functions (`marmot-c/src/lib.rs:66,213,246,300,342,416`). They accept NULL or
    zero-initialised options, so a new field arrives as NULL at runtime (`:390-434`).
- So, once the flip lands, every constructor takes the deployment as a required argument. The ones that can't are
  removed.
  - For Swift and Kotlin, the changed signature is a build error at each call site.
  - For C, the changed prototype is a compile error for an unchanged caller. A NULL deployment, including one in
    zero-initialised options, is rejected before `AccountHome` opens.
  - A test per entry point shows a missing deployment never opens the keychain.
- `just binding-docs-gate` checks only callables, not records or defaults (`scripts/check_binding_docs.py`). The
  binding READMEs ("Runtime options", "Service endpoint defaults", `marmot-uniffi/README.md:241-358`) are rewritten
  by hand. Their claim that a `None` profile-image server disables uploads becomes true once the primal fallback
  goes; downloads of peers' avatars are unaffected.

## PR sequence

Each PR is green on its own. PRs 1 and 2 change no default behaviour.

1. **Add `MarmotDeployment` and route every consumer through it.** `MarmotAppConfig::default()` still uses
   `white_noise()`.
   - Move the onboarding indexers, the group- and profile-image servers, new-group media servers, Open Ranking and
     the KeyPackage preference from constants to the record.
   - Report staging reads the moderation namespace from the record.
   - Delete the constants.
   - `MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS` still applies. `MarmotAppConfig::default()` lays a list set at build
     time over the preset's media servers, as `compiled()` does today. PR 3 removes it.
   - `MarmotServiceEndpoints` keeps only the collector routes (analytics, telemetry, audit), which step 6 owns.
   - `MarmotAppConfig` gains a field, which breaks struct literals, so this PR adds a CHANGELOG entry.
2. **Bindings and hosts.**
   - Add the UniFFI record and constructors, `MarmotOptions.deployment` (optional for now, defaulting to White
     Noise), and the C mirror.
   - The keychain name goes through the record.
   - The CLI and `wn-agent` call `MarmotDeployment::white_noise()` explicitly. The agent keeps its own
     messaging-relay constant.
   - The simulator and tests choose explicitly and keep their current behaviour. Moving a test to `neutral()` is a
     change of its own.
3. **The flip, in a minor release.**
   - `MarmotAppConfig::default()` returns `neutral()`.
   - Every binding constructor requires a deployment (see "Binding surface"), and a NULL one is rejected before the
     account home opens.
   - `MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS` goes; hosts pass the list.
   - The neutral behaviour lands: new groups follow decision 3, and profile-image uploads have no fallback.
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
  - a group created without media servers follows decision 3, and a media send says why;
  - the profile-image upload refuses, while a peer's avatar still downloads from its profile URL;
  - a report destination without a namespace is refused.
  - The `marmot-uniffi` smoke tests open with each preset.

## Risks

| Risk | Mitigation |
| --- | --- |
| White Noise apps upgrade without choosing the preset and lose keychain secrets | Every constructor requires a deployment after the flip: a build error in Swift and Kotlin, a compile error for an unchanged C caller, and a rejection before the keychain opens for a NULL one |
| A host passes the White Noise relays spelled differently and rebuilds every recovery scope | The preset is the one source; the hash input stays the raw sorted strings, as today |
| Hosts that share groups disagree on the group-image server | Unchanged from today: a client built with another value already disagrees. Recording the server in group state (out of scope below) removes it |
| A group created without an encrypted-media component can't get one later (`groups.rs:1789-1793`) | Decision 3 chooses between text-only groups and refusing creation. Enabling media later would need a commit that adds the component, which no API offers today |
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

Approved on 2026-10-18 as recommended: the preset lives in MDK, the neutral keychain service is
`org.marmot-protocol.mdk`, a new group without media servers is created text-only, and every binding constructor
requires a deployment after the flip.

1. **An opt-in White Noise preset inside MDK** (recommended), or no preset, with the White Noise apps holding the
   values themselves. Without one, the CLI and `wn-agent` would need their own copy.
2. **The neutral keychain service name.** The proposal is `org.marmot-protocol.mdk`. It matters only for hosts that
   never set one, because with a required binding field the White Noise apps always do.
3. **What "no media servers" means for a new group.**
   - Recommended: create it without an encrypted-media component. It stays text-only for life, because
     `replace_encrypted_media_blob_endpoints` refuses such a group. This suits text-only hosts.
   - Alternative: refuse group creation until the host sets servers. That forces a host that never sends media to
     configure servers anyway.
4. **Every binding constructor requires a deployment after the flip** (recommended, because of the keychain risk), or
   the constructors default to neutral.
