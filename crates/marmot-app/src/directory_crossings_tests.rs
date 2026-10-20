//! The directory's crossings into the rest of `marmot-app` (step 3 of
//! `docs/marmot-architecture/review/brief-directory.md`).
//!
//! The directory moves into its own crate once its production code names
//! nothing else in `marmot-app`. Until then, every name it resolves outside
//! `directory/` is listed in `src/directory/crossings.txt`, one line per file
//! and target. A crossing missing from the list fails, and so does a listed
//! one that no longer occurs, so the list only shrinks.
//!
//! A crossing is one of:
//! - a `crate::` path or `use crate::` leaf outside `directory/`, recorded up to
//!   its first type-like segment (`crate::AppError`, `crate::sqlcipher::database_open_lock`).
//!   A crate-root name that `lib.rs` re-exports from `directory::` is the
//!   directory's own and does not count;
//! - a `super::` path that climbs out of `directory/`, counting inline modules;
//! - a call to a `MarmotApp` method defined outside `directory/`
//!   (`MarmotApp::account_home()`), or a read of a `MarmotApp` field
//!   (`MarmotApp.relay_plane`), through `self` in a `MarmotApp` impl or through
//!   a binding with an `app` word in its name (`app`, `app_for_plan`, `cached_app`).
//!   `Self::name` in a `MarmotApp` impl and `MarmotApp::name` count as calls;
//! - any path into `marmot_account` or `marmot_app`, which the new crate must
//!   not depend on. Today's are listed like any other crossing, so they must be
//!   gone before the move.
//!
//! Code compiled only in test builds (`#[test]`, and a `cfg` that is false
//! without `test`, with the files such items declare) is not scanned. The scan
//! is by name, so it misses a hub reached through a binding with another name;
//! when the code moves, the compiler checks whatever is left. The walk and the
//! test-only rules follow `storage-sqlite`'s boundary test.

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

const ALLOW_LIST: &str = include_str!("directory/crossings.txt");
const ALLOW_LIST_PATH: &str = "src/directory/crossings.txt";
const DIRECTORY: &str = "directory/";
/// Crates the extracted directory must not depend on.
const FORBIDDEN_CRATES: &[&str] = &["marmot_account", "marmot_app"];

#[test]
fn directory_crossings_match_the_allow_list() {
    let files = production_files();
    let hub = Hub::collect(&files);
    assert!(
        !hub.fields.is_empty() && !hub.methods.is_empty(),
        "the scan found no `MarmotApp` fields or methods; update it for the new layout"
    );
    let mut found = BTreeSet::new();
    for file in files.iter().filter(|file| file.rel.starts_with(DIRECTORY)) {
        for target in crossings(file, &hub) {
            found.insert(format!("{} {target}", file.rel));
        }
    }
    let listed: BTreeSet<String> = ALLOW_LIST
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    let new: Vec<_> = found.difference(&listed).collect();
    let stale: Vec<_> = listed.difference(&found).collect();
    if new.is_empty() && stale.is_empty() {
        return;
    }
    let mut message = String::new();
    if !new.is_empty() {
        let _ = writeln!(
            message,
            "{} crossing(s) from directory/ into the rest of marmot-app are not on \
             {ALLOW_LIST_PATH}. Remove them, or list them:",
            new.len()
        );
        for line in &new {
            let _ = writeln!(message, "{line}");
        }
    }
    if !stale.is_empty() {
        let _ = writeln!(
            message,
            "{} listed crossing(s) no longer occur. Delete them from {ALLOW_LIST_PATH}:",
            stale.len()
        );
        for line in &stale {
            let _ = writeln!(message, "{line}");
        }
    }
    panic!("{message}");
}

#[test]
fn the_scan_sees_each_kind_of_crossing() {
    let source = r#"
        use crate::{AppError, sqlcipher::database_open_lock, directory::records::Record};
        use marmot_account::AccountSummary;
        use crate::UserDirectoryRecord;
        impl MarmotApp {
            fn f(&self) {
                let _ = self.account_home();
                let _ = &self.relay_plane;
                let _ = crate::ProductFamily::Directory;
                let _ = super::super::unix_now_seconds();
                let _ = format!("{}", self.shared_storage().is_ok());
            }
            fn through_paths(&self) {
                let _ = Self::relay_endpoints(self);
                assert!(Self::outbox_endpoints(self).is_empty());
            }
            #[cfg(test)]
            fn only_in_tests(&self) {
                let _ = self.deployment();
            }
        }
        fn h(app: &MarmotApp) {
            let _ = MarmotApp::account_dir(app, "label");
        }
        mod inner {
            fn i() {
                let _ = super::super::records::own_helper();
                let _ = super::super::super::push_unique_strings();
            }
        }
        fn g(app_for_accounts: MarmotApp, cached_app: MarmotApp) {
            let _ = app_for_accounts.root;
            let _ = cached_app.deployment();
            let _ = other.root;
            let _ = response.status();
            let _ = apply.deployment();
        }
    "#;
    let file = SourceFile {
        rel: "directory/example.rs".to_owned(),
        ast: syn::parse_file(source).unwrap(),
    };
    let hub = Hub {
        fields: ["relay_plane", "root"].map(str::to_owned).into(),
        methods: [
            "account_home",
            "shared_storage",
            "deployment",
            "status",
            "relay_endpoints",
            "outbox_endpoints",
            "account_dir",
        ]
        .map(str::to_owned)
        .into(),
        directory_reexports: ["UserDirectoryRecord"].map(str::to_owned).into(),
    };
    let found: Vec<String> = crossings(&file, &hub).into_iter().collect();
    assert_eq!(
        found,
        [
            "MarmotApp.relay_plane",
            "MarmotApp.root",
            "MarmotApp::account_dir()",
            "MarmotApp::account_home()",
            "MarmotApp::deployment()",
            "MarmotApp::outbox_endpoints()",
            "MarmotApp::relay_endpoints()",
            "MarmotApp::shared_storage()",
            "crate::AppError",
            "crate::ProductFamily",
            "crate::push_unique_strings",
            "crate::sqlcipher::database_open_lock",
            "crate::unix_now_seconds",
            "marmot_account::AccountSummary",
        ]
    );
}

/// One production source file, with its path relative to `src/`.
struct SourceFile {
    rel: String,
    ast: syn::File,
}

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Production files reachable from `lib.rs` through `mod` declarations that are
/// not test-only.
fn production_files() -> Vec<SourceFile> {
    let mut files = Vec::new();
    walk_file(&src_dir().join("lib.rs"), &mut files);
    files
}

fn walk_file(path: &Path, files: &mut Vec<SourceFile>) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let ast = syn::parse_file(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let dir = path.parent().unwrap().to_path_buf();
    let stem = path.file_stem().unwrap().to_str().unwrap();
    let child_dir = if stem == "lib" || stem == "mod" {
        dir.clone()
    } else {
        dir.join(stem)
    };
    walk_items(&ast.items, &dir, &child_dir, false, files);
    let rel = path
        .strip_prefix(src_dir())
        .unwrap()
        .to_str()
        .unwrap()
        .replace('\\', "/");
    files.push(SourceFile { rel, ast });
}

/// Follows `mod x;` declarations. `file_dir` is the declaring file's directory
/// (where `#[path]` resolves outside inline modules); `child_dir` is where
/// undecorated children live.
fn walk_items(
    items: &[syn::Item],
    file_dir: &Path,
    child_dir: &Path,
    inline: bool,
    files: &mut Vec<SourceFile>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if is_test_only(&module.attrs) {
            continue;
        }
        let name = module.ident.to_string();
        let explicit = module.attrs.iter().find_map(|attr| {
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
        match &module.content {
            Some((_, inner)) => {
                let dir = child_dir.join(&name);
                walk_items(inner, &dir, &dir, true, files);
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
                walk_file(&path, files);
            }
        }
    }
}

/// Whether these attributes compile the item only in test builds: `#[test]`,
/// or a `cfg` that is false whenever `test` is.
fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Meta>()
                    .is_ok_and(|p| cfg_without_test(&p) == Some(false)))
    })
}

/// A `cfg` predicate's value in a build without `test`: `Some` when that alone
/// decides it, `None` when it depends on the target or features.
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

fn is_hub_impl(item: &syn::ItemImpl) -> bool {
    item.trait_.is_none()
        && matches!(&*item.self_ty, syn::Type::Path(p)
            if p.path.segments.last().is_some_and(|s| s.ident == "MarmotApp"))
}

/// `MarmotApp`'s fields, the methods its impls outside `directory/` define, and
/// the crate-root names `lib.rs` re-exports from `directory::`.
struct Hub {
    fields: BTreeSet<String>,
    methods: BTreeSet<String>,
    directory_reexports: BTreeSet<String>,
}

impl Hub {
    fn collect(files: &[SourceFile]) -> Self {
        let mut hub = Hub {
            fields: BTreeSet::new(),
            methods: BTreeSet::new(),
            directory_reexports: BTreeSet::new(),
        };
        if let Some(lib) = files.iter().find(|file| file.rel == "lib.rs") {
            for item in &lib.ast.items {
                if let syn::Item::Use(item_use) = item
                    && !is_test_only(&item_use.attrs)
                {
                    directory_leaves(
                        &item_use.tree,
                        &mut Vec::new(),
                        &mut hub.directory_reexports,
                    );
                }
            }
        }
        for file in files {
            let outside = !file.rel.starts_with(DIRECTORY);
            let mut collector = HubCollector {
                hub: &mut hub,
                outside,
            };
            collector.visit_file(&file.ast);
        }
        hub
    }
}

/// The names a `use directory::...` tree brings into the crate root.
fn directory_leaves(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut BTreeSet<String>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            directory_leaves(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) if prefix.first().is_some_and(|s| s == "directory") => {
            out.insert(n.ident.to_string());
        }
        syn::UseTree::Rename(r) if prefix.first().is_some_and(|s| s == "directory") => {
            out.insert(r.rename.to_string());
        }
        syn::UseTree::Group(g) => {
            for item in &g.items {
                directory_leaves(item, prefix, out);
            }
        }
        _ => {}
    }
}

struct HubCollector<'a> {
    hub: &'a mut Hub,
    outside: bool,
}

impl<'ast> Visit<'ast> for HubCollector<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !starts_test_only(item.to_token_stream()) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if item.ident == "MarmotApp"
            && let syn::Fields::Named(fields) = &item.fields
        {
            self.hub.fields.extend(
                fields
                    .named
                    .iter()
                    .filter_map(|field| field.ident.as_ref().map(ToString::to_string)),
            );
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !(self.outside && is_hub_impl(item)) {
            return;
        }
        for impl_item in &item.items {
            if let syn::ImplItem::Fn(method) = impl_item
                && !is_test_only(&method.attrs)
            {
                self.hub.methods.insert(method.sig.ident.to_string());
            }
        }
    }
}

/// Every crossing in one `directory/` file, as allow-list targets.
fn crossings(file: &SourceFile, hub: &Hub) -> BTreeSet<String> {
    let mut scan = Scan {
        hub,
        module: module_path(&file.rel),
        in_hub_impl: false,
        found: BTreeSet::new(),
    };
    for item in &file.ast.items {
        scan.visit_item(item);
    }
    scan.found
}

/// The module path of a file under `src/`: `directory/cache/mod.rs` is
/// `directory::cache`, `directory/methods.rs` is `directory::methods`.
fn module_path(rel: &str) -> Vec<String> {
    let trimmed = rel.trim_end_matches(".rs");
    let mut segments: Vec<String> = trimmed.split('/').map(str::to_owned).collect();
    if segments.last().is_some_and(|s| s == "mod") {
        segments.pop();
    }
    segments
}

struct Scan<'a> {
    hub: &'a Hub,
    module: Vec<String>,
    in_hub_impl: bool,
    found: BTreeSet<String>,
}

impl Scan<'_> {
    /// Records a path when it leaves `directory/` or enters a forbidden crate.
    fn path(&mut self, segments: &[String]) {
        let Some(first) = segments.first() else {
            return;
        };
        // `Self::name` in a hub impl and `MarmotApp::name` anywhere reach the
        // hub as surely as `self.name()`.
        if let [ty, name] = segments
            && ((ty == "Self" && self.in_hub_impl) || ty == "MarmotApp")
            && self.hub.methods.contains(name)
        {
            self.found.insert(format!("MarmotApp::{name}()"));
            return;
        }
        if FORBIDDEN_CRATES.contains(&first.as_str()) && segments.len() > 1 {
            self.found.insert(truncate(segments));
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
            || absolute[0] == "directory"
            || self.hub.directory_reexports.contains(&absolute[0])
        {
            return;
        }
        let mut path = vec!["crate".to_owned()];
        path.extend(absolute);
        self.found.insert(truncate(&path));
    }

    /// `self` inside a `MarmotApp` impl, or a binding named for the app.
    fn is_hub(&self, receiver: &str) -> bool {
        (receiver == "self" && self.in_hub_impl) || receiver.split('_').any(|word| word == "app")
    }

    fn method_call(&mut self, receiver: &str, name: &str) {
        if self.is_hub(receiver) && self.hub.methods.contains(name) {
            self.found.insert(format!("MarmotApp::{name}()"));
        }
    }

    fn field(&mut self, receiver: &str, name: &str) {
        if self.is_hub(receiver) && self.hub.fields.contains(name) {
            self.found.insert(format!("MarmotApp.{name}"));
        }
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

    /// `crate::`/`super::` paths, `.name(` calls and `receiver.field` reads in
    /// macro arguments, which `syn` leaves as tokens.
    fn tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (i, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    if name == "crate"
                        || name == "super"
                        || name == "Self"
                        || name == "MarmotApp"
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
                        if path.len() > 1 && !(name == "super" && path.iter().all(|s| s == "super"))
                        {
                            self.path(&path);
                        }
                    }
                    if let (Some(TokenTree::Punct(dot)), Some(TokenTree::Ident(member))) =
                        (trees.get(i + 1), trees.get(i + 2))
                        && dot.as_char() == '.'
                    {
                        let member = member.to_string();
                        if matches!(trees.get(i + 3), Some(TokenTree::Group(g)) if g.delimiter() == proc_macro2::Delimiter::Parenthesis)
                        {
                            self.method_call(&name, &member);
                        } else {
                            self.field(&name, &member);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// A target recorded up to its first type-like segment, so enum variants and
/// associated items collapse onto their type: `crate::AppError::Storage` is
/// `crate::AppError`.
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

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_attribute(&mut self, _: &'ast syn::Attribute) {
        // Doc comments and `cfg`s are not code.
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        if starts_test_only(item.to_token_stream()) {
            return;
        }
        if let syn::Item::Mod(module) = item
            && module.content.is_none()
        {
            return; // Its file is scanned on its own.
        }
        if let syn::Item::Use(item_use) = item {
            self.use_tree(&item_use.tree, &mut Vec::new());
            return;
        }
        if let syn::Item::Mod(module) = item {
            // An inline module is one more level for `super::` to climb.
            self.module.push(module.ident.to_string());
            visit::visit_item(self, item);
            self.module.pop();
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let outer = self.in_hub_impl;
        self.in_hub_impl = is_hub_impl(item);
        visit::visit_item_impl(self, item);
        self.in_hub_impl = outer;
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if !starts_test_only(item.to_token_stream()) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        if !starts_test_only(stmt.to_token_stream()) {
            visit::visit_stmt(self, stmt);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.path(&segments);
        visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if let syn::Expr::Path(receiver) = &*call.receiver
            && let Some(ident) = receiver.path.get_ident()
        {
            self.method_call(&ident.to_string(), &call.method.to_string());
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(member) = &field.member
            && let syn::Expr::Path(receiver) = &*field.base
            && let Some(ident) = receiver.path.get_ident()
        {
            self.field(&ident.to_string(), &member.to_string());
        }
        visit::visit_expr_field(self, field);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
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
