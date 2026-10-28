//! Step 6's crossing check (#2627, PR 0).
//!
//! The diagnostics exporters move into `marmot-observability` once the code that moves names
//! nothing else in `marmot-app`, and nothing that stays reaches into its private fields. Until
//! then every crossing is listed in `src/observability_crossings.txt`, one line per scope, file
//! and target. A crossing missing from the list fails, and so does a listed one that no longer
//! occurs, so the list only shrinks.
//!
//! [`MOVING_SET`] names the code that moves.
//!
//! A crossing is one of:
//! - a name the moving set resolves in the rest of `marmot-app`:
//!   - a `crate::` path or `use crate::` leaf outside the set, recorded up to its first type-like
//!     segment (`crate::network_proxy::http_builder`, `crate::config::RelayTelemetryResource`).
//!     Crate-root re-exports of other crates count (`crate::MarmotRelayPlane`); a crate-root
//!     name that `lib.rs` re-exports from the set is the set's own;
//!   - a `super::` path that climbs out of the set, counting inline modules;
//!   - `AppError`, `MarmotApp` or `MarmotAppRuntime`, however they are named, recorded as
//!     `crate::AppError` and so on;
//!   - an impl block of `MarmotApp` or `MarmotAppRuntime`, recorded as `impl MarmotApp`;
//!   - a path into a crate the new crate must not depend on ([`FORBIDDEN_CRATES`]).
//! - a reach into a field that a type defined in the set does not declare `pub`, from code that
//!   stays: code outside the set, and `MarmotApp` and `MarmotAppRuntime` impl blocks inside it.
//!   Recorded as `field product_analytics::ProductAnalytics.clock`.
//!
//! Each entry is `production` or `test`. Test code is code compiled only in test builds:
//! `#[test]` items, items under a `cfg` that is false without `test`, and the files such items
//! declare.
//!
//! After cutting crossings, regenerate the list:
//!
//! ```sh
//! MARMOT_APP_REGENERATE_CROSSINGS=1 cargo nextest run -p marmot-app --lib -E 'test(observability_crossings)'
//! ```
//!
//! Regenerating refuses to add a line. A change to [`MOVING_SET`] may add lines, and is
//! regenerated with `MARMOT_APP_REGENERATE_CROSSINGS=grow`.
//!
//! The scan reads source, not types, so it can miss a crossing. When the code moves, the
//! compiler checks whatever is left.
//! - Paths are matched by name. A name brought in through a glob from outside the set is seen
//!   only at the glob (`crate::*`).
//! - A field access counts only when the scan can tell its receiver is the moving type. It
//!   follows `self`, written types, calls to functions and methods this crate defines, fields of
//!   structs it defines, and the std adapters in [`TRANSPARENT_METHODS`]. A name bound by a
//!   `let`, `match`, `if let`, `while let` or `for` pattern, or as a parameter of a closure passed
//!   to a std adapter, takes the type of the value it matches, within its scope. Generics are
//!   read loosely: an `Option<Pinned>` or a `Vec<Pinned>` holds a `Pinned`. Struct literals and
//!   patterns count by their path. Receivers the scan can't type are not counted: values only a
//!   trait method, a generic function or a macro produces, and the parameters of a closure
//!   passed to this crate's own functions.
//!
//! The walk and the test-only rules follow `storage-sqlite`'s boundary test and the directory's
//! crossing check (#2501).

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

/// The code step 6 moves into `marmot-observability` (#2627, "The shape"): the modules that move
/// whole, by module path. `audit_upload` is the audit upload half PR 3 split out of
/// `audit_log.rs`; `export_config` is what PR 4 split out of `config.rs` (the exporters' resolved
/// config and the endpoint parsers).
const MOVING_SET: &[&str] = &[
    "app_telemetry",
    "audit_otlp_sender",
    "audit_upload",
    "collector_host_safety",
    "export_config",
    "observer",
    "product_analytics",
    "relay_telemetry_export",
    "wiring",
];

/// Crates the new crate must not depend on (#2627, "The crate's dependencies"): `marmot-app`,
/// the account, session and storage crates beneath it, and `fs-private`.
const FORBIDDEN_CRATES: &[&str] = &[
    "fs_private",
    "marmot_account",
    "marmot_app",
    "marmot_session",
    "media_store",
    "rusqlite",
    "storage_sqlite",
];

/// The runtime types whose impl blocks and names count wherever the set names them.
const HUB_TYPES: &[&str] = &["MarmotApp", "MarmotAppRuntime"];
const APP_ERROR: &str = "AppError";

/// Methods whose result the scan treats as their receiver's type, for the std, `Option`,
/// `Result` and iterator adapters that sit between a binding and the value it holds. The scan
/// reads generics loosely: an `Option<Pinned>`, or an iterator over a `Vec<Pinned>`, holds a
/// `Pinned`.
const TRANSPARENT_METHODS: &[&str] = &[
    "as_mut",
    "as_ref",
    "borrow",
    "borrow_mut",
    "clone",
    "cloned",
    "copied",
    "expect",
    "filter",
    "first",
    "flatten",
    "get",
    "get_mut",
    "into_iter",
    "iter",
    "iter_mut",
    "last",
    "lock",
    "map_err",
    "next",
    "pop",
    "read",
    "remove",
    "rev",
    "take",
    "unwrap",
    "unwrap_or_else",
    "values",
    "values_mut",
    "write",
];

/// Adapters whose closure takes an accumulator before the item.
const FOLDS: &[&str] = &["fold", "rfold", "scan", "try_fold", "try_rfold"];

const LIST: &str = include_str!("observability_crossings.txt");
const LIST_PATH: &str = "src/observability_crossings.txt";
const REGENERATE: &str = "MARMOT_APP_REGENERATE_CROSSINGS";
const LIST_HEADER: &str = "\
# Crossings between the code step 6 moves into marmot-observability and the rest of marmot-app
# (#2627). Generated by src/observability_crossings_tests.rs, which documents each kind; do not
# edit by hand. Regenerate with:
#   MARMOT_APP_REGENERATE_CROSSINGS=1 cargo nextest run -p marmot-app --lib -E 'test(observability_crossings)'
# <production|test> <file under src/> <crossing>
";

#[test]
fn observability_crossings_match_the_list() {
    let files = source_files();
    for module in MOVING_SET {
        assert!(
            files.iter().any(|file| file.module.join("::") == *module),
            "MOVING_SET names `{module}`, which no file declares; update it for the new layout"
        );
    }
    let index = Index::build(&files, MOVING_SET);
    for hub in HUB_TYPES {
        assert!(
            index.by_name.contains_key(*hub),
            "the scan found no `{hub}` type; update it for the new layout"
        );
    }
    let found = scan(&files, &index);
    let listed = parse_list(LIST);
    if let Some(mode) = std::env::var_os(REGENERATE) {
        let text = regenerated(&found, &listed, mode == "grow").unwrap_or_else(|e| panic!("{e}"));
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(LIST_PATH);
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        return;
    }
    if let Err(message) = compare(&found, &listed) {
        panic!("{message}");
    }
}

#[test]
fn regenerating_refuses_to_add_a_line() {
    let listed: BTreeSet<String> = ["production a.rs crate::x", "test a.rs crate::y"]
        .map(str::to_owned)
        .into();
    let shrunk: BTreeSet<String> = ["test a.rs crate::y"].map(str::to_owned).into();
    let grown: BTreeSet<String> = ["test a.rs crate::y", "test b.rs crate::z"]
        .map(str::to_owned)
        .into();
    let text = regenerated(&shrunk, &listed, false).unwrap();
    assert_eq!(parse_list(&text), shrunk);
    let message = regenerated(&grown, &listed, false).unwrap_err();
    assert!(message.contains("test b.rs crate::z"), "{message}");
    assert_eq!(
        parse_list(&regenerated(&grown, &listed, true).unwrap()),
        grown
    );
}

#[test]
fn the_scan_sees_each_kind_of_crossing() {
    let files = fixture(&[
        (
            "lib.rs",
            r#"
            mod telemetry;
            mod config;
            pub use telemetry::{Permit, Shared as Renamed};
            pub use telemetry::*;
            pub use other_crate::Plane;
            pub struct MarmotApp {}
            pub struct MarmotAppRuntime {}
            pub fn unix_now() -> u64 { 0 }
            "#,
        ),
        ("config.rs", "pub struct Endpoint;"),
        (
            "telemetry.rs",
            r#"
            use crate::{AppError, MarmotApp, Plane, config::Endpoint};
            use crate::{Permit as OwnPermit, Renamed, Collector, telemetry::Own};
            use storage_sqlite::Row;
            pub struct Collector;
            pub struct Permit;
            pub struct Shared;
            pub struct Own;
            pub struct Hooks { #[cfg(test)] hook: crate::TestHook }
            impl MarmotApp {
                fn consent(&self) {}
            }
            impl crate::MarmotAppRuntime {}
            fn errors() -> Result<(), crate::error::AppError> {
                let _ = format!("{}", crate::unix_now());
                Ok(())
            }
            mod inner {
                fn climbs() {
                    let _ = super::super::install_id();
                    let _ = super::Own;
                    let _ = self::Local;
                }
            }
            #[cfg(test)]
            mod tests {
                use super::*;
                fn only_in_tests() {
                    assert!(matches!(AppError::Busy, AppError::Busy));
                    let _ = MarmotApp::open();
                }
            }
            "#,
        ),
    ]);
    assert_eq!(
        found_in(&files, &["telemetry"]),
        [
            "production telemetry.rs crate::AppError",
            "production telemetry.rs crate::MarmotApp",
            "production telemetry.rs crate::Plane",
            "production telemetry.rs crate::config::Endpoint",
            "production telemetry.rs crate::install_id",
            "production telemetry.rs crate::unix_now",
            "production telemetry.rs impl MarmotApp",
            "production telemetry.rs impl MarmotAppRuntime",
            "production telemetry.rs storage_sqlite::Row",
            "test telemetry.rs crate::AppError",
            "test telemetry.rs crate::MarmotApp",
            "test telemetry.rs crate::TestHook",
        ]
    );
}

#[test]
fn the_scan_sees_each_field_reach() {
    let files = fixture(&[
        (
            "lib.rs",
            r#"
            mod telemetry;
            mod reach;
            pub use telemetry::{Collector, Permit, Pinned};
            pub struct MarmotApp { analytics: Collector }
            "#,
        ),
        (
            "telemetry.rs",
            r#"
            use crate::MarmotApp;
            pub struct Collector { pub(crate) rejected: bool, clock: u8, pub public: u8 }
            pub struct Permit { pub(crate) id: String }
            pub struct Pinned { pub(crate) url: String }
            pub struct Counter(pub(crate) u64);
            struct State { persisted: bool }
            pub fn resolve() -> Result<Pinned, ()> { todo!() }
            impl Collector {
                fn lock(&self) -> std::sync::MutexGuard<'_, State> { todo!() }
                fn own(&self) -> u8 { self.clock }
            }
            impl MarmotApp {
                fn consent(&self) -> u8 { self.analytics.clock }
            }
            "#,
        ),
        (
            "reach/params.rs",
            "fn f(permit: &crate::Permit) -> &str { &permit.id }",
        ),
        (
            "reach/chains.rs",
            "impl crate::MarmotApp { fn f(&self) -> bool { self.analytics.rejected } }",
        ),
        (
            "reach/calls.rs",
            r#"
            fn f() -> String {
                let pin = crate::telemetry::resolve().map_err(|_| ()).unwrap();
                pin.url
            }
            "#,
        ),
        (
            "reach/methods.rs",
            r#"
            fn f(app: &crate::MarmotApp) -> bool {
                let state = app.analytics.lock();
                state.persisted
            }
            "#,
        ),
        (
            "reach/literals.rs",
            "fn f() -> crate::Pinned { crate::Pinned { url: String::new() } }",
        ),
        (
            "reach/patterns.rs",
            "fn f(c: crate::Collector) -> bool { let crate::Collector { rejected, .. } = c; rejected }",
        ),
        (
            "reach/tuples.rs",
            "fn f(c: crate::telemetry::Counter) -> u64 { c.0 }",
        ),
        (
            "reach/macros.rs",
            "fn f(app: crate::MarmotApp) { assert!(app.analytics.rejected); }",
        ),
        (
            "reach/matches.rs",
            r#"
            fn f(maybe: Option<crate::Pinned>) -> String {
                match maybe { Some(pin) => pin.url, None => String::new() }
            }
            "#,
        ),
        (
            "reach/if_let.rs",
            r#"
            fn f(maybe: Option<crate::Permit>, ready: bool) -> String {
                if ready && let Some(permit) = &maybe { permit.id.clone() } else { String::new() }
            }
            "#,
        ),
        (
            "reach/while_let.rs",
            r#"
            fn f(mut pending: Vec<crate::Permit>) -> usize {
                let mut n = 0;
                while let Some(permit) = pending.pop() { n += permit.id.len(); }
                n
            }
            "#,
        ),
        (
            "reach/let_else.rs",
            r#"
            fn f(result: Result<crate::telemetry::Counter, ()>) -> u64 {
                let Ok(counter) = result else { return 0 };
                counter.0
            }
            "#,
        ),
        (
            "reach/destructured.rs",
            r#"
            fn f(app: crate::MarmotApp) -> bool {
                let crate::MarmotApp { analytics, .. } = app;
                analytics.rejected
            }
            "#,
        ),
        (
            "reach/for_loops.rs",
            r#"
            fn f(collectors: &[crate::Collector]) -> usize {
                let mut n = 0;
                for collector in collectors.iter() { if collector.rejected { n += 1; } }
                n
            }
            "#,
        ),
        (
            "reach/closures.rs",
            r#"
            fn f(pins: Vec<crate::Pinned>) -> Vec<String> {
                pins.into_iter().map(|pin| pin.url).collect()
            }
            "#,
        ),
        (
            "reach/tests.rs",
            r#"
            #[cfg(test)]
            fn f(app: crate::MarmotApp) -> u8 { app.analytics.clock }
            "#,
        ),
    ]);
    assert_eq!(
        found_in(&files, &["telemetry"]),
        [
            "production reach/calls.rs field telemetry::Pinned.url",
            "production reach/chains.rs field telemetry::Collector.rejected",
            "production reach/closures.rs field telemetry::Pinned.url",
            "production reach/destructured.rs field telemetry::Collector.rejected",
            "production reach/for_loops.rs field telemetry::Collector.rejected",
            "production reach/if_let.rs field telemetry::Permit.id",
            "production reach/let_else.rs field telemetry::Counter.0",
            "production reach/literals.rs field telemetry::Pinned.url",
            "production reach/macros.rs field telemetry::Collector.rejected",
            "production reach/matches.rs field telemetry::Pinned.url",
            "production reach/methods.rs field telemetry::State.persisted",
            "production reach/params.rs field telemetry::Permit.id",
            "production reach/patterns.rs field telemetry::Collector.rejected",
            "production reach/tuples.rs field telemetry::Counter.0",
            "production reach/while_let.rs field telemetry::Permit.id",
            "production telemetry.rs crate::MarmotApp",
            "production telemetry.rs field telemetry::Collector.clock",
            "production telemetry.rs impl MarmotApp",
            "test reach/tests.rs field telemetry::Collector.clock",
        ]
    );
}

/// A field access counts only when the receiver is shown to be the moving type, so a field of
/// the same name on another type, or on a receiver the scan can't type, is not listed. A name is
/// typed by its innermost binding in scope.
#[test]
fn field_reaches_need_the_receivers_type() {
    let files = fixture(&[
        (
            "lib.rs",
            r#"
            mod telemetry;
            pub use telemetry::Pinned;
            pub struct Proxy { pub url: String }
            fn other_type(proxy: Proxy) -> String { proxy.url }
            fn unknown_call() -> String { let pin = make(); pin.url }
            fn out_of_scope(maybe: Option<Pinned>) -> String {
                let pin = Proxy { url: String::new() };
                if let Some(pin) = maybe { drop(pin); }
                match maybe { Some(_) => pin.url, None => pin.url }
            }
            fn shadowed(pin: Pinned) -> String { let pin = Proxy { url: pin.public.to_string() }; pin.url }
            fn accumulator(pins: Vec<Pinned>, start: Proxy) -> Proxy {
                pins.iter().fold(start, |acc, _| { drop(acc.url); acc })
            }
            fn public_field(pin: Pinned) -> u8 { pin.public }
            fn both_types(pair: Result<Proxy, Pinned>) -> String { pair.unwrap().url }
            "#,
        ),
        (
            "telemetry.rs",
            r#"
            pub struct Pinned { pub(crate) url: String, pub public: u8 }
            fn inside(pin: Pinned) -> String { pin.url }
            "#,
        ),
    ]);
    assert_eq!(found_in(&files, &["telemetry"]), Vec::<String>::new());
}

#[test]
fn an_added_crossing_fails_the_check() {
    let mut files = source_files();
    let file = files
        .iter_mut()
        .find(|file| !file.test && file.module.join("::") == MOVING_SET[0])
        .unwrap();
    file.ast.items.push(syn::parse_quote! {
        fn added() -> u64 { crate::observability_crossing_probe() }
    });
    let rel = file.rel.clone();
    // And a reach into a restricted field from `lib.rs`, through a `match` binding.
    let (field, owners) = Index::build(&files, MOVING_SET)
        .doors
        .into_iter()
        .next()
        .expect("the set has no restricted field");
    let owner = owners.first().unwrap();
    let lib = files
        .iter_mut()
        .find(|file| file.module.is_empty())
        .unwrap();
    lib.ast.items.push(
        syn::parse_str(&format!(
            "fn added_reach(maybe: Option<{owner}>) {{ \
                match maybe {{ Some(value) => drop(value.{field}), None => {{}} }} \
            }}"
        ))
        .unwrap(),
    );
    let index = Index::build(&files, MOVING_SET);
    let message = compare(&scan(&files, &index), &parse_list(LIST)).unwrap_err();
    for added in [
        format!("production {rel} crate::observability_crossing_probe"),
        format!("production lib.rs field {}.{field}", display_type(owner)),
    ] {
        assert!(message.contains(&added), "{added} not in: {message}");
    }
}

#[test]
fn a_stale_entry_fails_the_check() {
    let files = source_files();
    let index = Index::build(&files, MOVING_SET);
    let found = scan(&files, &index);
    let stale = "production product_analytics/mod.rs crate::no_longer_named".to_owned();
    let mut listed = found.clone();
    listed.insert(stale.clone());
    let message = compare(&found, &listed).unwrap_err();
    assert!(message.contains(&stale), "{message}");
    assert!(compare(&found, &found).is_ok());
}

/// A type the set defines must keep its inherent methods with it: an `impl` of it elsewhere is a
/// dependency the crossing list cannot see, and cannot survive the move (inherent impls must
/// live in the defining crate).
#[test]
fn moving_types_have_no_inherent_impls_outside_the_set() {
    let files = source_files();
    let stray = outside_inherent_impls(&files, &Index::build(&files, MOVING_SET));
    assert!(
        stray.is_empty(),
        "inherent impls of moving types outside the moving set; move them next to the type:\n{}",
        stray.join("\n")
    );
}

#[test]
fn the_impl_check_sees_an_outside_inherent_impl() {
    let files = fixture(&[
        (
            "lib.rs",
            "mod telemetry; pub struct Shared; impl telemetry::Status { fn f() {} } impl Clone for telemetry::Status { fn clone(&self) -> Self { todo!() } } impl Shared {}",
        ),
        ("telemetry.rs", "pub struct Status; pub struct Shared;"),
    ]);
    // `Shared` in `lib.rs` is its own type; a trait impl is not an inherent impl.
    assert_eq!(
        outside_inherent_impls(&files, &Index::build(&files, &["telemetry"])),
        ["lib.rs impl telemetry::Status"]
    );
}

/// Inherent impls outside the set, of types the set defines.
fn outside_inherent_impls(files: &[SourceFile], index: &Index) -> Vec<String> {
    let mut stray = Vec::new();
    for file in files {
        let mut impls = InherentImpls {
            index,
            file,
            module: file.module.clone(),
            found: Vec::new(),
        };
        for item in &file.ast.items {
            impls.visit_item(item);
        }
        stray.extend(impls.found);
    }
    stray.sort();
    stray.dedup();
    stray
}

struct InherentImpls<'a> {
    index: &'a Index,
    file: &'a SourceFile,
    module: Vec<String>,
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for InherentImpls<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        self.module.push(item.ident.to_string());
        visit::visit_item_mod(self, item);
        self.module.pop();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if item.trait_.is_some() || self.index.in_set(&self.module) {
            return;
        }
        if let syn::Type::Path(p) = &*item.self_ty {
            let key = self
                .index
                .resolve_path(&self.file.rel, &self.module, &p.path, None);
            if self.index.moving_types.contains(&key) {
                self.found
                    .push(format!("{} impl {}", self.file.rel, display_type(&key)));
            }
        }
    }
}

/// One source file, with its path relative to `src/`, its module path, and whether it is
/// compiled only in test builds.
struct SourceFile {
    rel: String,
    module: Vec<String>,
    test: bool,
    ast: syn::File,
}

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every file reachable from `lib.rs` through `mod` declarations.
fn source_files() -> Vec<SourceFile> {
    let mut files = Vec::new();
    walk_file(&src_dir().join("lib.rs"), Vec::new(), false, &mut files);
    files
}

/// In-memory files for the scanner's own tests; a file's module path follows its name.
fn fixture(sources: &[(&str, &str)]) -> Vec<SourceFile> {
    sources
        .iter()
        .map(|(rel, source)| SourceFile {
            rel: (*rel).to_owned(),
            module: if *rel == "lib.rs" {
                Vec::new()
            } else {
                rel.trim_end_matches(".rs")
                    .split('/')
                    .map(str::to_owned)
                    .collect()
            },
            test: false,
            ast: syn::parse_file(source).unwrap(),
        })
        .collect()
}

fn found_in(files: &[SourceFile], moving: &[&str]) -> Vec<String> {
    scan(files, &Index::build(files, moving))
        .into_iter()
        .collect()
}

fn walk_file(path: &Path, module: Vec<String>, test: bool, files: &mut Vec<SourceFile>) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let ast = syn::parse_file(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let dir = path.parent().unwrap().to_path_buf();
    let stem = path.file_stem().unwrap().to_str().unwrap();
    let child_dir = if stem == "lib" || stem == "mod" {
        dir.clone()
    } else {
        dir.join(stem)
    };
    walk_items(&ast.items, &dir, &child_dir, false, &module, test, files);
    let rel = path
        .strip_prefix(src_dir())
        .unwrap()
        .to_str()
        .unwrap()
        .replace('\\', "/");
    files.push(SourceFile {
        rel,
        module,
        test,
        ast,
    });
}

/// Follows `mod x;` declarations. `file_dir` is the declaring file's directory (where `#[path]`
/// resolves outside inline modules); `child_dir` is where undecorated children live.
fn walk_items(
    items: &[syn::Item],
    file_dir: &Path,
    child_dir: &Path,
    inline: bool,
    module: &[String],
    test: bool,
    files: &mut Vec<SourceFile>,
) {
    for item in items {
        let syn::Item::Mod(declared) = item else {
            continue;
        };
        let name = declared.ident.to_string();
        let test = test || is_test_only(&declared.attrs);
        let mut child = module.to_vec();
        child.push(name.clone());
        let explicit = declared.attrs.iter().find_map(|attr| {
            let syn::Meta::NameValue(nv) = &attr.meta else {
                return None;
            };
            if !nv.path.is_ident("path") {
                return None;
            }
            let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) = &nv.value
            else {
                return None;
            };
            Some(s.value())
        });
        match &declared.content {
            Some((_, inner)) => {
                let dir = child_dir.join(&name);
                walk_items(inner, &dir, &dir, true, &child, test, files);
            }
            None => {
                let path = match explicit {
                    Some(p) if inline => child_dir.join(p),
                    Some(p) => file_dir.join(p),
                    None if child_dir.join(format!("{name}.rs")).exists() => {
                        child_dir.join(format!("{name}.rs"))
                    }
                    None => child_dir.join(&name).join("mod.rs"),
                };
                walk_file(&path, child, test, files);
            }
        }
    }
}

/// Whether these attributes compile the item only in test builds: `#[test]`, or a `cfg` that is
/// false whenever `test` is.
fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Meta>()
                    .is_ok_and(|p| cfg_without_test(&p) == Some(false)))
    })
}

/// A `cfg` predicate's value in a build without `test`: `Some` when that alone decides it,
/// `None` when it depends on the target or features.
fn cfg_without_test(predicate: &syn::Meta) -> Option<bool> {
    match predicate {
        syn::Meta::Path(path) if path.is_ident("test") => Some(false),
        syn::Meta::List(list) => {
            let args = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .ok()?;
            let values: Vec<Option<bool>> = args.iter().map(cfg_without_test).collect();
            if list.path.is_ident("not") {
                values.first().copied().flatten().map(|v| !v)
            } else if list.path.is_ident("all") {
                if values.contains(&Some(false)) {
                    Some(false)
                } else if values.iter().all(|v| *v == Some(true)) {
                    Some(true)
                } else {
                    None
                }
            } else if list.path.is_ident("any") {
                if values.contains(&Some(true)) {
                    Some(true)
                } else if values.iter().all(|v| *v == Some(false)) {
                    Some(false)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Whether an item, statement or expression is compiled only in test builds.
fn starts_test_only(tokens: TokenStream) -> bool {
    let parser = |input: syn::parse::ParseStream| {
        let attrs = syn::Attribute::parse_outer(input)?;
        input.parse::<TokenStream>()?;
        Ok(attrs)
    };
    is_test_only(&syn::parse::Parser::parse2(parser, tokens).unwrap_or_default())
}

/// A `use` leaf: the module it sits in, and the path it names.
type Import = (Vec<String>, Vec<String>);

/// What the scan knows about the crate's types, keyed `crate::<module>::<Name>`.
#[derive(Default)]
struct Index {
    moving: Vec<Vec<String>>,
    /// Struct and enum keys by name.
    by_name: BTreeMap<String, BTreeSet<String>>,
    /// Struct and enum keys by the file that defines them, then by name.
    file_types: BTreeMap<String, BTreeMap<String, String>>,
    /// Each file's `mod` declarations, and each `use` leaf with the module it sits in and the
    /// path it names.
    file_modules: BTreeMap<String, BTreeSet<String>>,
    file_imports: BTreeMap<String, BTreeMap<String, Import>>,
    /// The types each struct field's type names, by owner key and field name (`0` for the first
    /// tuple field).
    fields: BTreeMap<(String, String), BTreeSet<String>>,
    /// The types each function's return type names: methods by owner key and name, free
    /// functions by name.
    methods: BTreeMap<(String, String), BTreeSet<String>>,
    free_fns: BTreeMap<String, Vec<BTreeSet<String>>>,
    /// Types the set defines, and their fields that are not `pub`, by field name.
    moving_types: BTreeSet<String>,
    doors: BTreeMap<String, BTreeSet<String>>,
    /// Crate-root names `lib.rs` re-exports from the set.
    set_exports: BTreeSet<String>,
}

impl Index {
    fn build(files: &[SourceFile], moving: &[&str]) -> Self {
        let mut index = Index {
            moving: moving
                .iter()
                .map(|m| m.split("::").map(str::to_owned).collect())
                .collect(),
            ..Index::default()
        };
        for file in files {
            let mut types = TypeDefinitions {
                index: &mut index,
                file,
                module: file.module.clone(),
            };
            for item in &file.ast.items {
                types.visit_item(item);
            }
        }
        for file in files {
            let mut members = Members {
                index: &mut index,
                file,
                module: file.module.clone(),
                self_ty: None,
            };
            for item in &file.ast.items {
                members.visit_item(item);
            }
        }
        if let Some(lib) = files.iter().find(|file| file.module.is_empty()) {
            let mut exports = BTreeSet::new();
            for item in &lib.ast.items {
                if let syn::Item::Use(item_use) = item
                    && !is_test_only(&item_use.attrs)
                {
                    index.set_leaves(files, &item_use.tree, &mut Vec::new(), &mut exports);
                }
            }
            index.set_exports = exports;
        }
        index
    }

    /// Whether a module or item path lies in the moving set.
    fn in_set(&self, path: &[String]) -> bool {
        self.moving.iter().any(|m| path.starts_with(m))
    }

    /// The crate-root names a `lib.rs` `use` tree brings in from the set.
    fn set_leaves(
        &self,
        files: &[SourceFile],
        tree: &syn::UseTree,
        prefix: &mut Vec<String>,
        out: &mut BTreeSet<String>,
    ) {
        match tree {
            syn::UseTree::Path(p) => {
                if !(prefix.is_empty() && (p.ident == "crate" || p.ident == "self")) {
                    prefix.push(p.ident.to_string());
                }
                self.set_leaves(files, &p.tree, prefix, out);
                prefix.pop();
            }
            syn::UseTree::Name(n) if self.in_set(prefix) => {
                out.insert(n.ident.to_string());
            }
            syn::UseTree::Rename(r) if self.in_set(prefix) => {
                out.insert(r.rename.to_string());
            }
            syn::UseTree::Glob(_) if self.in_set(prefix) => {
                module_exports(files, prefix, out);
            }
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    self.set_leaves(files, item, prefix, out);
                }
            }
            _ => {}
        }
    }

    /// The key a path names, resolved from `module` in `file`; an unresolved name keeps a `?`.
    fn resolve_path(
        &self,
        file: &str,
        module: &[String],
        path: &syn::Path,
        self_ty: Option<&str>,
    ) -> String {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.resolve_segments(file, module, &segments, self_ty)
    }

    fn resolve_segments(
        &self,
        file: &str,
        module: &[String],
        segments: &[String],
        self_ty: Option<&str>,
    ) -> String {
        match segments {
            [] => "?".to_owned(),
            [name] if name == "Self" => self_ty.map_or_else(|| "?Self".to_owned(), str::to_owned),
            [name] => {
                if let Some(key) = self.file_types.get(file).and_then(|t| t.get(name)) {
                    return key.clone();
                }
                if let Some((from, path)) = self.file_imports.get(file).and_then(|i| i.get(name))
                    && path.len() > 1
                {
                    return self.resolve_segments(file, from, path, self_ty);
                }
                self.unique(name)
            }
            [first, rest @ ..] => {
                let last = segments.last().unwrap();
                let base = match first.as_str() {
                    "crate" => Vec::new(),
                    "self" => module.to_vec(),
                    "super" => {
                        let climbs = segments.iter().take_while(|s| *s == "super").count();
                        let Some(keep) = module.len().checked_sub(climbs) else {
                            return format!("?{last}");
                        };
                        let mut base = module[..keep].to_vec();
                        base.extend(segments[climbs..segments.len() - 1].iter().cloned());
                        return self.key_or_unique(base, last);
                    }
                    _ if self
                        .file_modules
                        .get(file)
                        .is_some_and(|m| m.contains(first)) =>
                    {
                        let mut base = module.to_vec();
                        base.push(first.clone());
                        base
                    }
                    _ => return format!("?{last}"),
                };
                let mut base = base;
                base.extend(rest[..rest.len() - 1].iter().cloned());
                self.key_or_unique(base, last)
            }
        }
    }

    /// The key at `module::name` if the crate defines one there, else the crate's only type of
    /// that name.
    fn key_or_unique(&self, module: Vec<String>, name: &str) -> String {
        let key = type_key(&module, name);
        if self
            .by_name
            .get(name)
            .is_some_and(|keys| keys.contains(&key))
        {
            key
        } else {
            self.unique(name)
        }
    }

    fn unique(&self, name: &str) -> String {
        match self.by_name.get(name) {
            Some(keys) if keys.len() == 1 => keys.first().unwrap().clone(),
            _ => format!("?{name}"),
        }
    }

    /// The keys a type names, resolved from `module` in `file`.
    fn type_keys(
        &self,
        file: &str,
        module: &[String],
        ty: &syn::Type,
        self_ty: Option<&str>,
    ) -> BTreeSet<String> {
        let mut names = TypeNames {
            index: self,
            file,
            module,
            self_ty,
            out: BTreeSet::new(),
        };
        names.visit_type(ty);
        names.out
    }

    fn field_types(&self, owners: &BTreeSet<String>, field: &str) -> Option<BTreeSet<String>> {
        let mut out = BTreeSet::new();
        let mut known = false;
        for owner in owners {
            if let Some(types) = self.fields.get(&(owner.clone(), field.to_owned())) {
                out.extend(types.iter().cloned());
                known = true;
            }
        }
        known.then_some(out)
    }

    fn method_returns(&self, owners: &BTreeSet<String>, method: &str) -> Option<BTreeSet<String>> {
        let mut out = BTreeSet::new();
        let mut known = false;
        for owner in owners {
            if let Some(types) = self.methods.get(&(owner.clone(), method.to_owned())) {
                out.extend(types.iter().cloned());
                known = true;
            }
        }
        known.then_some(out)
    }

    /// What a free function of this name returns, if every function of that name agrees.
    fn free_fn_returns(&self, name: &str) -> Option<BTreeSet<String>> {
        let mut candidates = self.free_fns.get(name)?.iter();
        let first = candidates.next()?.clone();
        Some(candidates.fold(first, |acc, types| {
            acc.intersection(types).cloned().collect()
        }))
    }
}

fn type_key(module: &[String], name: &str) -> String {
    let mut key = String::from("crate");
    for segment in module {
        key.push_str("::");
        key.push_str(segment);
    }
    key.push_str("::");
    key.push_str(name);
    key
}

/// A key as the list shows it: `crate::product_analytics::State` is `product_analytics::State`.
fn display_type(key: &str) -> &str {
    key.strip_prefix("crate::").unwrap_or(key)
}

/// The names a module brings into scope for a glob import of it: its non-private items and
/// re-exports, following globs into the set.
fn module_exports(files: &[SourceFile], module: &[String], out: &mut BTreeSet<String>) {
    let Some(file) = files.iter().find(|file| file.module == module) else {
        return;
    };
    for item in &file.ast.items {
        if starts_test_only(item.to_token_stream()) {
            continue;
        }
        let (vis, ident) = match item {
            syn::Item::Const(i) => (&i.vis, &i.ident),
            syn::Item::Enum(i) => (&i.vis, &i.ident),
            syn::Item::Fn(i) => (&i.vis, &i.sig.ident),
            syn::Item::Mod(i) => (&i.vis, &i.ident),
            syn::Item::Static(i) => (&i.vis, &i.ident),
            syn::Item::Struct(i) => (&i.vis, &i.ident),
            syn::Item::Trait(i) => (&i.vis, &i.ident),
            syn::Item::Type(i) => (&i.vis, &i.ident),
            syn::Item::Union(i) => (&i.vis, &i.ident),
            syn::Item::Use(i) => {
                if !matches!(i.vis, syn::Visibility::Inherited) {
                    use_exports(files, module, &i.tree, &mut Vec::new(), out);
                }
                continue;
            }
            _ => continue,
        };
        if !matches!(vis, syn::Visibility::Inherited) {
            out.insert(ident.to_string());
        }
    }
}

fn use_exports(
    files: &[SourceFile],
    module: &[String],
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    out: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            use_exports(files, module, &p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            out.insert(n.ident.to_string());
        }
        syn::UseTree::Rename(r) => {
            out.insert(r.rename.to_string());
        }
        syn::UseTree::Glob(_) => {
            let mut child = module.to_vec();
            child.extend(prefix.iter().filter(|s| *s != "self").cloned());
            if child.len() > module.len() {
                module_exports(files, &child, out);
            }
        }
        syn::UseTree::Group(g) => {
            for item in &g.items {
                use_exports(files, module, item, prefix, out);
            }
        }
    }
}

/// First pass: every struct and enum, and each file's modules and imports.
struct TypeDefinitions<'a> {
    index: &'a mut Index,
    file: &'a SourceFile,
    module: Vec<String>,
}

impl TypeDefinitions<'_> {
    fn define(&mut self, name: &syn::Ident) {
        let name = name.to_string();
        let key = type_key(&self.module, &name);
        self.index
            .by_name
            .entry(name.clone())
            .or_default()
            .insert(key.clone());
        self.index
            .file_types
            .entry(self.file.rel.clone())
            .or_default()
            .entry(name)
            .or_insert(key);
    }

    fn import(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        let mut add = |leaf: String, path: Vec<String>| {
            self.index
                .file_imports
                .entry(self.file.rel.clone())
                .or_default()
                .entry(leaf)
                .or_insert((self.module.clone(), path));
        };
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.import(&p.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(n) if n.ident != "self" => {
                let mut path = prefix.clone();
                path.push(n.ident.to_string());
                add(n.ident.to_string(), path);
            }
            syn::UseTree::Rename(r) => {
                let mut path = prefix.clone();
                path.push(r.ident.to_string());
                add(r.rename.to_string(), path);
            }
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    self.import(item, prefix);
                }
            }
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for TypeDefinitions<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        self.index
            .file_modules
            .entry(self.file.rel.clone())
            .or_default()
            .insert(item.ident.to_string());
        self.module.push(item.ident.to_string());
        visit::visit_item_mod(self, item);
        self.module.pop();
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.import(&item.tree, &mut Vec::new());
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.define(&item.ident);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        self.define(&item.ident);
    }
}

/// Second pass: field types, function return types, and the set's non-`pub` fields.
struct Members<'a> {
    index: &'a mut Index,
    file: &'a SourceFile,
    module: Vec<String>,
    self_ty: Option<String>,
}

impl Members<'_> {
    fn returns(&self, output: &syn::ReturnType) -> BTreeSet<String> {
        match output {
            syn::ReturnType::Default => BTreeSet::new(),
            syn::ReturnType::Type(_, ty) => {
                self.index
                    .type_keys(&self.file.rel, &self.module, ty, self.self_ty.as_deref())
            }
        }
    }
}

impl<'ast> Visit<'ast> for Members<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        self.module.push(item.ident.to_string());
        visit::visit_item_mod(self, item);
        self.module.pop();
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        let owner = type_key(&self.module, &item.ident.to_string());
        let moving = self.index.in_set(&self.module);
        if moving {
            self.index.moving_types.insert(owner.clone());
        }
        for (position, field) in item.fields.iter().enumerate() {
            let name = field
                .ident
                .as_ref()
                .map_or_else(|| position.to_string(), ToString::to_string);
            let types = self
                .index
                .type_keys(&self.file.rel, &self.module, &field.ty, Some(&owner));
            self.index
                .fields
                .insert((owner.clone(), name.clone()), types);
            if moving && !matches!(field.vis, syn::Visibility::Public(_)) {
                self.index
                    .doors
                    .entry(name)
                    .or_default()
                    .insert(owner.clone());
            }
        }
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if self.index.in_set(&self.module) {
            self.index
                .moving_types
                .insert(type_key(&self.module, &item.ident.to_string()));
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let types = self.returns(&item.sig.output);
        self.index
            .free_fns
            .entry(item.sig.ident.to_string())
            .or_default()
            .push(types);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let syn::Type::Path(p) = &*item.self_ty else {
            return;
        };
        let owner = self
            .index
            .resolve_path(&self.file.rel, &self.module, &p.path, None);
        let outer = self.self_ty.replace(owner.clone());
        for impl_item in &item.items {
            if let syn::ImplItem::Fn(method) = impl_item {
                let types = self.returns(&method.sig.output);
                self.index
                    .methods
                    .entry((owner.clone(), method.sig.ident.to_string()))
                    .or_default()
                    .extend(types);
            }
        }
        self.self_ty = outer;
    }
}

struct TypeNames<'a> {
    index: &'a Index,
    file: &'a str,
    module: &'a [String],
    self_ty: Option<&'a str>,
    out: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for TypeNames<'_> {
    fn visit_type_path(&mut self, ty: &'ast syn::TypePath) {
        if ty.qself.is_none() {
            self.out.insert(self.index.resolve_path(
                self.file,
                self.module,
                &ty.path,
                self.self_ty,
            ));
        }
        visit::visit_type_path(self, ty);
    }
}

/// The names one block, arm, closure or function binds, with the types the scan can tell each
/// holds (`None` when it can't).
#[derive(Default)]
struct Scope {
    names: BTreeMap<String, Option<BTreeSet<String>>>,
    /// A function's own scope: names outside it are not in scope.
    item: bool,
}

/// Every crossing, as `<production|test> <file> <target>` lines.
fn scan(files: &[SourceFile], index: &Index) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for file in files {
        let mut scan = Scan {
            index,
            file,
            module: file.module.clone(),
            test: file.test,
            hub_impl: false,
            self_ty: None,
            scopes: Vec::new(),
            found: BTreeSet::new(),
        };
        for item in &file.ast.items {
            scan.visit_item(item);
        }
        for (test, target) in scan.found {
            let scope = if test { "test" } else { "production" };
            found.insert(format!("{scope} {} {target}", file.rel));
        }
    }
    found
}

fn parse_list(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

/// The list regeneration writes. It adds no line unless `grow`, which only a change to
/// [`MOVING_SET`] uses.
fn regenerated(
    found: &BTreeSet<String>,
    listed: &BTreeSet<String>,
    grow: bool,
) -> Result<String, String> {
    let added: Vec<&str> = found.difference(listed).map(String::as_str).collect();
    if !added.is_empty() && !grow {
        return Err(format!(
            "regenerating would add {} crossing(s) to {LIST_PATH}. Remove them; only a change \
             to MOVING_SET may add lines, with {REGENERATE}=grow:\n{}",
            added.len(),
            added.join("\n")
        ));
    }
    let mut text = LIST_HEADER.to_owned();
    for line in found {
        let _ = writeln!(text, "{line}");
    }
    Ok(text)
}

fn compare(found: &BTreeSet<String>, listed: &BTreeSet<String>) -> Result<(), String> {
    let new: Vec<_> = found.difference(listed).collect();
    let stale: Vec<_> = listed.difference(found).collect();
    if new.is_empty() && stale.is_empty() {
        return Ok(());
    }
    let mut message = String::new();
    if !new.is_empty() {
        let _ = writeln!(
            message,
            "{} crossing(s) between the moving set and the rest of marmot-app are not on \
             {LIST_PATH}. Remove them; only a change to MOVING_SET may add lines (see \
             observability_crossings_tests.rs):",
            new.len()
        );
        for line in &new {
            let _ = writeln!(message, "{line}");
        }
    }
    if !stale.is_empty() {
        let _ = writeln!(
            message,
            "{} listed crossing(s) no longer occur. Regenerate {LIST_PATH} with \
             {REGENERATE}=1 (see observability_crossings_tests.rs):",
            stale.len()
        );
        for line in &stale {
            let _ = writeln!(message, "{line}");
        }
    }
    Err(message)
}

/// A target recorded up to its first type-like segment, so enum variants and associated items
/// collapse onto their type: `crate::config::RelayTelemetryResource::default` is
/// `crate::config::RelayTelemetryResource`.
fn truncate(path: &[String]) -> String {
    let mut out = Vec::new();
    for segment in path {
        out.push(segment.as_str());
        if segment.chars().next().is_some_and(char::is_uppercase) {
            break;
        }
    }
    out.join("::")
}

struct Scan<'a> {
    index: &'a Index,
    file: &'a SourceFile,
    module: Vec<String>,
    test: bool,
    /// Inside an impl block of `MarmotApp` or `MarmotAppRuntime`.
    hub_impl: bool,
    self_ty: Option<String>,
    /// The scopes around the code being scanned, innermost last.
    scopes: Vec<Scope>,
    /// `(test, target)`.
    found: BTreeSet<(bool, String)>,
}

impl<'a> Scan<'a> {
    fn record(&mut self, target: String) {
        self.found.insert((self.test, target));
    }

    /// Whether the current code moves: names it resolves outside the set are crossings.
    fn moves(&self) -> bool {
        self.index.in_set(&self.module)
    }

    /// Whether the current code stays in `marmot-app`: reaches into the set's private fields
    /// are crossings.
    fn stays(&self) -> bool {
        !self.moves() || self.hub_impl
    }

    /// Records a path the moving set names outside itself.
    fn path(&mut self, segments: &[String]) {
        if !self.moves() {
            return;
        }
        let Some(first) = segments.first() else {
            return;
        };
        if let Some(hub) = segments
            .iter()
            .find(|s| *s == APP_ERROR || HUB_TYPES.contains(&s.as_str()))
        {
            self.record(format!("crate::{hub}"));
            return;
        }
        if FORBIDDEN_CRATES.contains(&first.as_str()) && segments.len() > 1 {
            self.record(truncate(segments));
            return;
        }
        let absolute = match first.as_str() {
            "crate" => segments[1..].to_vec(),
            "super" => {
                let climbs = segments.iter().take_while(|s| *s == "super").count();
                let Some(keep) = self.module.len().checked_sub(climbs) else {
                    return;
                };
                let mut path = self.module[..keep].to_vec();
                path.extend(segments[climbs..].iter().cloned());
                path
            }
            _ => return,
        };
        if absolute.is_empty()
            || self.index.in_set(&absolute)
            || self.index.set_exports.contains(&absolute[0])
        {
            return;
        }
        let mut path = vec!["crate".to_owned()];
        path.extend(absolute);
        self.record(truncate(&path));
    }

    fn use_tree(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.use_tree(&p.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(n) => {
                let mut path = prefix.clone();
                if n.ident != "self" {
                    path.push(n.ident.to_string());
                }
                self.path(&path);
            }
            syn::UseTree::Rename(r) => {
                let mut path = prefix.clone();
                path.push(r.ident.to_string());
                self.path(&path);
            }
            syn::UseTree::Glob(_) => {
                let mut path = prefix.clone();
                path.push("*".to_owned());
                self.path(&path);
            }
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    self.use_tree(item, prefix);
                }
            }
        }
    }

    /// Records a reach into `field` of a value of these types, when one of them is a moving type
    /// that does not declare the field `pub`, and no other type among them has a field of that
    /// name.
    fn reach(&mut self, types: &BTreeSet<String>, field: &str) {
        let Some(owners) = self.index.doors.get(field) else {
            return;
        };
        let ambiguous = types.iter().any(|ty| {
            !self.index.moving_types.contains(ty)
                && self
                    .index
                    .fields
                    .contains_key(&(ty.clone(), field.to_owned()))
        });
        if ambiguous {
            return;
        }
        let reached: Vec<String> = owners.intersection(types).cloned().collect();
        for owner in reached {
            self.record(format!("field {}.{field}", display_type(&owner)));
        }
    }

    fn resolve(&self, path: &syn::Path) -> String {
        self.index
            .resolve_path(&self.file.rel, &self.module, path, self.self_ty.as_deref())
    }

    /// The types an expression's value names, when the scan can tell.
    fn types_of(&self, expr: &syn::Expr) -> Option<BTreeSet<String>> {
        match expr {
            syn::Expr::Path(p) if p.qself.is_none() => {
                let ident = p.path.get_ident()?.to_string();
                self.name_types(&ident)
            }
            syn::Expr::Field(f) => {
                let base = self.types_of(&f.base)?;
                self.index.field_types(&base, &member_name(&f.member))
            }
            syn::Expr::MethodCall(call) => {
                let receiver = self.types_of(&call.receiver)?;
                let method = call.method.to_string();
                self.index.method_returns(&receiver, &method).or_else(|| {
                    TRANSPARENT_METHODS
                        .contains(&method.as_str())
                        .then_some(receiver)
                })
            }
            syn::Expr::Call(call) => {
                let syn::Expr::Path(func) = &*call.func else {
                    return None;
                };
                self.call_returns(&func.path)
            }
            syn::Expr::Await(e) => self.types_of(&e.base),
            syn::Expr::Try(e) => self.types_of(&e.expr),
            syn::Expr::Paren(e) => self.types_of(&e.expr),
            syn::Expr::Group(e) => self.types_of(&e.expr),
            syn::Expr::Reference(e) => self.types_of(&e.expr),
            syn::Expr::Index(e) => self.types_of(&e.expr),
            syn::Expr::Unary(e) if matches!(e.op, syn::UnOp::Deref(_)) => self.types_of(&e.expr),
            syn::Expr::Struct(s) => Some(BTreeSet::from([self.resolve(&s.path)])),
            syn::Expr::Cast(c) => Some(self.type_keys(&c.ty)),
            _ => None,
        }
    }

    /// The types a name holds: `self`, or the innermost binding of it in the enclosing function.
    fn name_types(&self, name: &str) -> Option<BTreeSet<String>> {
        if name == "self" {
            return self.self_ty.clone().map(|ty| BTreeSet::from([ty]));
        }
        for scope in self.scopes.iter().rev() {
            if let Some(types) = scope.names.get(name) {
                return types.clone();
            }
            if scope.item {
                break;
            }
        }
        None
    }

    fn type_keys(&self, ty: &syn::Type) -> BTreeSet<String> {
        self.index
            .type_keys(&self.file.rel, &self.module, ty, self.self_ty.as_deref())
    }

    /// Binds the names a pattern introduces in the innermost scope, typing each from the value
    /// it matches: a written type as written, a struct pattern's field by its declared type, and
    /// anything else (tuples, references, `Some`, `Ok`) as the whole value, the way the scan reads
    /// generics.
    fn bind(&mut self, pat: &syn::Pat, types: Option<BTreeSet<String>>) {
        match pat {
            syn::Pat::Ident(p) => {
                if let Some((_, sub)) = &p.subpat {
                    self.bind(sub, types.clone());
                }
                if let Some(scope) = self.scopes.last_mut() {
                    scope.names.insert(p.ident.to_string(), types);
                }
            }
            syn::Pat::Type(p) => {
                let types = self.type_keys(&p.ty);
                self.bind(&p.pat, Some(types));
            }
            syn::Pat::Reference(p) => self.bind(&p.pat, types),
            syn::Pat::Paren(p) => self.bind(&p.pat, types),
            syn::Pat::Or(p) => {
                for case in &p.cases {
                    self.bind(case, types.clone());
                }
            }
            syn::Pat::Tuple(p) => {
                for elem in &p.elems {
                    self.bind(elem, types.clone());
                }
            }
            syn::Pat::Slice(p) => {
                for elem in &p.elems {
                    self.bind(elem, types.clone());
                }
            }
            syn::Pat::TupleStruct(p) => {
                let owner = BTreeSet::from([self.resolve(&p.path)]);
                // Positions after `..` are not known.
                let mut known = true;
                for (position, elem) in p.elems.iter().enumerate() {
                    known &= !matches!(elem, syn::Pat::Rest(_));
                    let elem_types = if known {
                        self.index
                            .field_types(&owner, &position.to_string())
                            .or_else(|| types.clone())
                    } else {
                        None
                    };
                    self.bind(elem, elem_types);
                }
            }
            syn::Pat::Struct(p) => {
                let owner = BTreeSet::from([self.resolve(&p.path)]);
                for field in &p.fields {
                    let declared = self.index.field_types(&owner, &member_name(&field.member));
                    self.bind(&field.pat, declared.or_else(|| types.clone()));
                }
            }
            _ => {}
        }
    }

    /// Visits code in a scope of its own.
    fn scoped(&mut self, item: bool, visit: impl FnOnce(&mut Self)) {
        self.scopes.push(Scope {
            item,
            ..Scope::default()
        });
        visit(self);
        self.scopes.pop();
    }

    /// Visits a function in its own scope, with its parameters bound.
    fn function(&mut self, sig: &syn::Signature, visit: impl FnOnce(&mut Self)) {
        self.scoped(true, |scan| {
            for input in &sig.inputs {
                if let syn::FnArg::Typed(param) = input {
                    let types = scan.type_keys(&param.ty);
                    scan.bind(&param.pat, Some(types));
                }
            }
            visit(scan);
        });
    }

    /// Visits a closure. A parameter without a written type holds `items`, the types of the
    /// value the closure's method was called on, except a fold's accumulator.
    fn closure(
        &mut self,
        closure: &'a syn::ExprClosure,
        items: Option<BTreeSet<String>>,
        fold: bool,
    ) {
        self.scoped(false, |scan| {
            for (position, input) in closure.inputs.iter().enumerate() {
                let items = (!(fold && position == 0)).then(|| items.clone()).flatten();
                scan.bind(input, items);
            }
            visit::visit_expr_closure(scan, closure);
        });
    }

    /// What a call to this path returns: `Type::f` and `Self::f` by the type's methods, a free
    /// function by its name.
    fn call_returns(&self, path: &syn::Path) -> Option<BTreeSet<String>> {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        let (name, owner) = segments.split_last()?;
        match owner.last() {
            Some(ty) if ty.chars().next().is_some_and(char::is_uppercase) => {
                let owner = self.index.resolve_segments(
                    &self.file.rel,
                    &self.module,
                    owner,
                    self.self_ty.as_deref(),
                );
                self.index.method_returns(&BTreeSet::from([owner]), name)
            }
            _ => self.index.free_fn_returns(name),
        }
    }

    /// Kind 2 in macro arguments, which `syn` leaves as tokens: `a.b.c` chains whose start the
    /// scan can type.
    fn token_chain(&mut self, trees: &[TokenTree], start: usize) {
        let TokenTree::Ident(first) = &trees[start] else {
            return;
        };
        let Some(mut types) = self.name_types(&first.to_string()) else {
            return;
        };
        let mut i = start + 1;
        while let (Some(TokenTree::Punct(dot)), Some(TokenTree::Ident(member))) =
            (trees.get(i), trees.get(i + 1))
        {
            if dot.as_char() != '.' {
                break;
            }
            let member = member.to_string();
            if matches!(trees.get(i + 2), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis)
            {
                let Some(next) = self.index.method_returns(&types, &member).or_else(|| {
                    TRANSPARENT_METHODS
                        .contains(&member.as_str())
                        .then(|| types.clone())
                }) else {
                    return;
                };
                types = next;
                i += 3;
            } else if member == "await" {
                i += 2;
            } else {
                self.reach(&types, &member);
                let Some(next) = self.index.field_types(&types, &member) else {
                    return;
                };
                types = next;
                i += 2;
            }
        }
    }

    /// Kind 1 paths and kind 2 chains in macro arguments.
    fn tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (i, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    let after_path_separator = i >= 2
                        && matches!((&trees[i - 2], &trees[i - 1]),
                            (TokenTree::Punct(a), TokenTree::Punct(b)) if a.as_char() == ':' && b.as_char() == ':');
                    let after_dot = i >= 1
                        && matches!(&trees[i - 1], TokenTree::Punct(p) if p.as_char() == '.');
                    if after_path_separator || after_dot {
                        continue;
                    }
                    let hub = name == APP_ERROR || HUB_TYPES.contains(&name.as_str());
                    if name == "crate"
                        || name == "super"
                        || hub
                        || FORBIDDEN_CRATES.contains(&name.as_str())
                    {
                        let mut path = vec![name.clone()];
                        let mut j = i + 1;
                        while let (
                            Some(TokenTree::Punct(a)),
                            Some(TokenTree::Punct(b)),
                            Some(TokenTree::Ident(next)),
                        ) = (trees.get(j), trees.get(j + 1), trees.get(j + 2))
                        {
                            if a.as_char() != ':' || b.as_char() != ':' {
                                break;
                            }
                            path.push(next.to_string());
                            j += 3;
                        }
                        if hub
                            || (path.len() > 1
                                && !(name == "super" && path.iter().all(|s| s == "super")))
                        {
                            self.path(&path);
                        }
                    }
                    if self.stays() {
                        self.token_chain(&trees, i);
                    }
                }
                _ => {}
            }
        }
    }
}

fn member_name(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(ident) => ident.to_string(),
        syn::Member::Unnamed(index) => index.index.to_string(),
    }
}

impl<'a> Visit<'a> for Scan<'a> {
    fn visit_attribute(&mut self, _: &'a syn::Attribute) {
        // Doc comments and `cfg`s are not code.
    }

    fn visit_item(&mut self, item: &'a syn::Item) {
        let outer = self.test;
        self.test |= starts_test_only(item.to_token_stream());
        match item {
            // Its file is scanned on its own.
            syn::Item::Mod(module) if module.content.is_none() => {}
            syn::Item::Mod(module) => {
                // An inline module is one more level for `super::` to climb.
                self.module.push(module.ident.to_string());
                visit::visit_item(self, item);
                self.module.pop();
            }
            syn::Item::Use(item_use) => self.use_tree(&item_use.tree, &mut Vec::new()),
            syn::Item::Fn(function) => {
                self.function(&function.sig, |scan| visit::visit_item(scan, item));
            }
            _ => visit::visit_item(self, item),
        }
        self.test = outer;
    }

    fn visit_item_impl(&mut self, item: &'a syn::ItemImpl) {
        let outer = (self.hub_impl, self.self_ty.take());
        let mut hub = None;
        if let syn::Type::Path(p) = &*item.self_ty {
            self.self_ty = Some(self.resolve(&p.path));
            hub = p
                .path
                .segments
                .last()
                .filter(|s| HUB_TYPES.iter().any(|h| s.ident == h))
                .map(|s| s.ident.to_string());
        }
        if let Some(hub) = hub {
            if self.moves() {
                self.record(format!("impl {hub}"));
            }
            // The impl entry covers naming the hub; visit everything but the self type.
            self.hub_impl = true;
            self.visit_generics(&item.generics);
            if let Some((_, path, _)) = &item.trait_ {
                self.visit_path(path);
            }
            for impl_item in &item.items {
                self.visit_impl_item(impl_item);
            }
        } else {
            visit::visit_item_impl(self, item);
        }
        (self.hub_impl, self.self_ty) = outer;
    }

    fn visit_impl_item(&mut self, item: &'a syn::ImplItem) {
        let outer = self.test;
        self.test |= starts_test_only(item.to_token_stream());
        if let syn::ImplItem::Fn(method) = item {
            self.function(&method.sig, |scan| visit::visit_impl_item(scan, item));
        } else {
            visit::visit_impl_item(self, item);
        }
        self.test = outer;
    }

    fn visit_trait_item(&mut self, item: &'a syn::TraitItem) {
        let outer = self.test;
        self.test |= starts_test_only(item.to_token_stream());
        match item {
            syn::TraitItem::Fn(method) => {
                self.function(&method.sig, |scan| visit::visit_trait_item(scan, item));
            }
            _ => visit::visit_trait_item(self, item),
        }
        self.test = outer;
    }

    fn visit_stmt(&mut self, stmt: &'a syn::Stmt) {
        let outer = self.test;
        self.test |= starts_test_only(stmt.to_token_stream());
        visit::visit_stmt(self, stmt);
        self.test = outer;
    }

    fn visit_block(&mut self, block: &'a syn::Block) {
        self.scoped(false, |scan| visit::visit_block(scan, block));
    }

    fn visit_local(&mut self, local: &'a syn::Local) {
        // The initialiser, and a let-else's `else`, see only the names bound before the `let`.
        if let Some(init) = &local.init {
            self.visit_local_init(init);
        }
        let types = local
            .init
            .as_ref()
            .and_then(|init| self.types_of(&init.expr));
        self.visit_pat(&local.pat);
        self.bind(&local.pat, types);
    }

    fn visit_expr_let(&mut self, expr: &'a syn::ExprLet) {
        self.visit_expr(&expr.expr);
        let types = self.types_of(&expr.expr);
        self.visit_pat(&expr.pat);
        self.bind(&expr.pat, types);
    }

    fn visit_expr_if(&mut self, expr: &'a syn::ExprIf) {
        // An `if let` binds for the rest of its condition and its then-branch.
        self.scoped(false, |scan| {
            scan.visit_expr(&expr.cond);
            scan.visit_block(&expr.then_branch);
        });
        if let Some((_, else_branch)) = &expr.else_branch {
            self.visit_expr(else_branch);
        }
    }

    fn visit_expr_while(&mut self, expr: &'a syn::ExprWhile) {
        self.scoped(false, |scan| {
            scan.visit_expr(&expr.cond);
            scan.visit_block(&expr.body);
        });
    }

    fn visit_expr_match(&mut self, expr: &'a syn::ExprMatch) {
        self.visit_expr(&expr.expr);
        let types = self.types_of(&expr.expr);
        for arm in &expr.arms {
            self.scoped(false, |scan| {
                scan.bind(&arm.pat, types.clone());
                scan.visit_arm(arm);
            });
        }
    }

    fn visit_expr_for_loop(&mut self, expr: &'a syn::ExprForLoop) {
        self.visit_expr(&expr.expr);
        let types = self.types_of(&expr.expr);
        self.scoped(false, |scan| {
            scan.visit_pat(&expr.pat);
            scan.bind(&expr.pat, types);
            scan.visit_block(&expr.body);
        });
    }

    fn visit_expr_closure(&mut self, closure: &'a syn::ExprClosure) {
        self.closure(closure, None, false);
    }

    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.visit_expr(&call.receiver);
        if let Some(turbofish) = &call.turbofish {
            self.visit_angle_bracketed_generic_arguments(turbofish);
        }
        // A closure passed to a std adapter (`map`, `any`, `retain`) takes the receiver's items.
        // One passed to this crate's own method takes what that method's bounds say, which the
        // scan does not read.
        let method = call.method.to_string();
        let items = self
            .types_of(&call.receiver)
            .filter(|receiver| self.index.method_returns(receiver, &method).is_none());
        let fold = FOLDS.contains(&method.as_str());
        for arg in &call.args {
            match arg {
                syn::Expr::Closure(closure) => self.closure(closure, items.clone(), fold),
                _ => self.visit_expr(arg),
            }
        }
    }

    fn visit_field(&mut self, field: &'a syn::Field) {
        let outer = self.test;
        self.test |= is_test_only(&field.attrs);
        visit::visit_field(self, field);
        self.test = outer;
    }

    fn visit_field_value(&mut self, field: &'a syn::FieldValue) {
        let outer = self.test;
        self.test |= is_test_only(&field.attrs);
        visit::visit_field_value(self, field);
        self.test = outer;
    }

    fn visit_arm(&mut self, arm: &'a syn::Arm) {
        let outer = self.test;
        self.test |= is_test_only(&arm.attrs);
        visit::visit_arm(self, arm);
        self.test = outer;
    }

    fn visit_variant(&mut self, variant: &'a syn::Variant) {
        let outer = self.test;
        self.test |= is_test_only(&variant.attrs);
        visit::visit_variant(self, variant);
        self.test = outer;
    }

    fn visit_path(&mut self, path: &'a syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.path(&segments);
        visit::visit_path(self, path);
    }

    fn visit_expr_field(&mut self, field: &'a syn::ExprField) {
        if self.stays()
            && let Some(types) = self.types_of(&field.base)
        {
            self.reach(&types, &member_name(&field.member));
        }
        visit::visit_expr_field(self, field);
    }

    fn visit_expr_struct(&mut self, expr: &'a syn::ExprStruct) {
        if self.stays() {
            let types = BTreeSet::from([self.resolve(&expr.path)]);
            let named: Vec<String> = expr.fields.iter().map(|f| member_name(&f.member)).collect();
            for field in &named {
                self.reach(&types, field);
            }
            if expr.rest.is_some() {
                // Functional update moves every field it does not name.
                let rest: Vec<String> = self
                    .index
                    .doors
                    .iter()
                    .filter(|(field, owners)| {
                        !named.contains(field) && owners.iter().any(|o| types.contains(o))
                    })
                    .map(|(field, _)| field.clone())
                    .collect();
                for field in rest {
                    self.reach(&types, &field);
                }
            }
        }
        visit::visit_expr_struct(self, expr);
    }

    fn visit_pat_struct(&mut self, pat: &'a syn::PatStruct) {
        if self.stays() {
            let types = BTreeSet::from([self.resolve(&pat.path)]);
            for field in &pat.fields {
                self.reach(&types, &member_name(&field.member));
            }
        }
        visit::visit_pat_struct(self, pat);
    }

    fn visit_pat_tuple_struct(&mut self, pat: &'a syn::PatTupleStruct) {
        if self.stays() {
            let types = BTreeSet::from([self.resolve(&pat.path)]);
            for position in 0..pat.elems.len() {
                self.reach(&types, &position.to_string());
            }
        }
        visit::visit_pat_tuple_struct(self, pat);
    }

    fn visit_macro(&mut self, mac: &'a syn::Macro) {
        let segments: Vec<String> = mac
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        self.path(&segments);
        self.tokens(mac.tokens.clone());
    }
}
