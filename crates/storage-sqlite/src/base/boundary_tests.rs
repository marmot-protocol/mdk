//! The boundary between the protocol and app sides of this crate (step 4 of
//! `docs/marmot-architecture/review/brief-storage-boundaries.md`).
//!
//! Every table has one owning side ([`super::table_owners`]). A production file
//! runs SQL only against its own side's tables and names only its own side's
//! modules and methods. Both sides may use `base`, which names neither. A file's
//! side is its folder; `cross/` may touch both, and `shared` is a separate
//! database.
//!
//! The crossings that remain are listed in `src/cross/allow-list.txt`, one line
//! per file and target. A crossing missing from the list fails, and so does a
//! listed one that no longer occurs, so the list only shrinks. Code compiled
//! only in test builds (`#[test]`, and a `cfg` that is false without `test`, with
//! the files such items declare) and migration bodies are not scanned; the
//! fresh-database checks cover the schema the migrations leave.
//!
//! The scan is by name. It reads string literals for table names, `crate::`
//! paths for modules, and calls through `self` or `Self` inside
//! `SqliteAccountStorage` impls for methods. A call to `app_storage()`, the
//! app handle, through any receiver counts as reaching the app side. It misses a table name assembled at
//! run time and a call through another binding of the storage.

use super::table_owners::{Side, TABLE_OWNERS, owner};
use crate::SqliteAccountStorage;
use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

const ALLOW_LIST: &str = include_str!("../cross/allow-list.txt");
const ALLOW_LIST_PATH: &str = "src/cross/allow-list.txt";

#[test]
fn table_registry_names_every_table() {
    let tables: BTreeSet<String> = fresh_schema().tables;
    let registered: BTreeSet<String> = TABLE_OWNERS.iter().map(|(t, _)| (*t).to_owned()).collect();
    let unowned: Vec<_> = tables.difference(&registered).collect();
    let gone: Vec<_> = registered.difference(&tables).collect();
    assert!(
        unowned.is_empty() && gone.is_empty(),
        "src/base/table_owners.rs must name every table of a fresh database exactly once.\n\
         Give these new tables an owning side: {unowned:?}\n\
         Remove these, which a fresh database no longer has: {gone:?}"
    );
    assert_eq!(
        registered.len(),
        TABLE_OWNERS.len(),
        "a table is registered twice"
    );
}

#[test]
fn storage_boundary_matches_the_allow_list() {
    let mut found = source_crossings();
    found.extend(schema_crossings());
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
            "{} crossing(s) between the protocol and app sides are not on {ALLOW_LIST_PATH}. \
             Move them into cross/, or list them:",
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

/// One production source file and the side its folder puts it on.
struct SourceFile {
    rel: String,
    side: Option<Side>,
    ast: syn::File,
}

/// Which side a file is on, or `None` when the boundary does not scan it.
fn side_of(rel: &str) -> Option<Side> {
    if rel.starts_with("base/migrations/") {
        return None; // Migration bodies: schema history.
    }
    match rel.split('/').next() {
        Some("protocol") => Some(Side::Protocol),
        Some("app") => Some(Side::App),
        Some("base") | Some("lib.rs") => Some(Side::Base),
        _ => None, // `cross/`, and `shared`, which is a separate database.
    }
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
    files.push(SourceFile {
        side: side_of(&rel),
        rel,
        ast,
    });
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
/// or a `cfg` that is false whenever `test` is. `not(test)` ships, and so does
/// `any(target_os = "android", test)`; only a predicate that cannot hold without
/// `test` makes an item test-only.
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

/// The outer attributes at the start of an item, statement or expression.
fn leading_attrs(tokens: TokenStream) -> Vec<syn::Attribute> {
    let parser = |input: syn::parse::ParseStream| {
        let attrs = syn::Attribute::parse_outer(input)?;
        input.parse::<TokenStream>()?;
        Ok(attrs)
    };
    syn::parse::Parser::parse2(parser, tokens).unwrap_or_default()
}

/// Whether an item, statement or expression is compiled only in test builds.
fn starts_test_only(tokens: TokenStream) -> bool {
    is_test_only(&leading_attrs(tokens))
}

/// What one file names: string literals, `crate::` paths, and calls through
/// `self` or `Self` inside `SqliteAccountStorage` impls.
#[derive(Default)]
struct Names {
    literals: Vec<String>,
    paths: BTreeSet<Vec<String>>,
    self_calls: BTreeSet<String>,
    /// Whether the file asks for the app handle (`app_storage()`), through any
    /// receiver: that hands out every method on `SqliteAppStorage`.
    app_handle_calls: bool,
}

struct Scan<'a> {
    names: &'a mut Names,
    in_storage_impl: bool,
}

fn is_storage_impl(item: &syn::ItemImpl) -> bool {
    matches!(&*item.self_ty, syn::Type::Path(p)
        if p.path.segments.last().is_some_and(|s| s.ident == "SqliteAccountStorage"))
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
            let mut prefix = Vec::new();
            use_paths(&item_use.tree, &mut prefix, &mut self.names.paths);
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let outer = self.in_storage_impl;
        self.in_storage_impl = is_storage_impl(item);
        visit::visit_item_impl(self, item);
        self.in_storage_impl = outer;
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

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.names.literals.push(lit.value());
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if segments.last().is_some_and(|s| s == "app_storage") {
            self.names.app_handle_calls = true;
        }
        if segments.first().is_some_and(|s| s == "crate") {
            self.names.paths.insert(segments);
        } else if self.in_storage_impl && segments.len() == 2 && segments[0] == "Self" {
            self.names.self_calls.insert(segments[1].clone());
        }
        visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "app_storage" {
            self.names.app_handle_calls = true;
        }
        if self.in_storage_impl
            && matches!(&*call.receiver, syn::Expr::Path(p) if p.path.is_ident("self"))
        {
            self.names.self_calls.insert(call.method.to_string());
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        scan_tokens(mac.tokens.clone(), self.in_storage_impl, self.names);
    }
}

fn use_paths(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut BTreeSet<Vec<String>>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            use_paths(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => leaf(prefix, n.ident.to_string(), out),
        syn::UseTree::Rename(r) => leaf(prefix, r.ident.to_string(), out),
        syn::UseTree::Glob(_) => {
            if prefix.first().is_some_and(|s| s == "crate") {
                out.insert(prefix.clone());
            }
        }
        syn::UseTree::Group(g) => g.items.iter().for_each(|t| use_paths(t, prefix, out)),
    }
}

fn leaf(prefix: &[String], name: String, out: &mut BTreeSet<Vec<String>>) {
    let mut path = prefix.to_vec();
    if name != "self" {
        path.push(name);
    }
    if path.first().is_some_and(|s| s == "crate") {
        out.insert(path);
    }
}

/// Literals, `crate::` paths and `self.x(` / `Self::x(` calls inside macro
/// arguments, which `syn` leaves as tokens.
fn scan_tokens(tokens: TokenStream, in_storage_impl: bool, names: &mut Names) {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Literal(lit) => {
                if let Ok(s) = syn::parse_str::<syn::LitStr>(&lit.to_string()) {
                    names.literals.push(s.value());
                }
            }
            TokenTree::Group(group) => scan_tokens(group.stream(), in_storage_impl, names),
            TokenTree::Ident(ident) if ident == "app_storage" => {
                names.app_handle_calls = true;
            }
            TokenTree::Ident(ident) if ident == "crate" => {
                let mut path = vec!["crate".to_owned()];
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
                if path.len() > 1 {
                    names.paths.insert(path);
                }
            }
            TokenTree::Ident(ident) if in_storage_impl && (ident == "self" || ident == "Self") => {
                let call = match (trees.get(i + 1), trees.get(i + 2), trees.get(i + 3)) {
                    (
                        Some(TokenTree::Punct(dot)),
                        Some(TokenTree::Ident(name)),
                        Some(TokenTree::Group(_)),
                    ) if ident == "self" && dot.as_char() == '.' => Some(name.to_string()),
                    (
                        Some(TokenTree::Punct(a)),
                        Some(TokenTree::Punct(b)),
                        Some(TokenTree::Ident(name)),
                    ) if ident == "Self" && a.as_char() == ':' && b.as_char() == ':' => {
                        Some(name.to_string())
                    }
                    _ => None,
                };
                names.self_calls.extend(call);
            }
            _ => {}
        }
    }
}

fn scan(file: &syn::File) -> Names {
    let mut names = Names::default();
    let mut visitor = Scan {
        names: &mut names,
        in_storage_impl: false,
    };
    for item in &file.items {
        visitor.visit_item(item);
    }
    names
}

/// The side a `crate::` path reaches, with the target recorded on the list:
/// the module for folder paths, the re-exported name for crate-root paths.
fn path_target(path: &[String], root: &BTreeMap<String, Side>) -> Option<(Side, String)> {
    let side = match path.get(1).map(String::as_str)? {
        "app" => Side::App,
        "protocol" => Side::Protocol,
        "base" => Side::Base,
        name => return root.get(name).map(|side| (*side, format!("crate::{name}"))),
    };
    // `storage` and `transport` are folders of modules; name the module inside them.
    let folder = path
        .get(2)
        .is_some_and(|s| s == "storage" || s == "transport");
    let depth = if folder { 4 } else { 3 };
    Some((side, path[..depth.min(path.len())].join("::")))
}

/// Crate-root names re-exported from a side folder, from `lib.rs`.
fn root_reexports(lib: &syn::File) -> BTreeMap<String, Side> {
    let mut map = BTreeMap::new();
    for item in &lib.items {
        let syn::Item::Use(item_use) = item else {
            continue;
        };
        let mut paths = BTreeSet::new();
        let mut prefix = vec!["crate".to_owned()];
        use_paths(&item_use.tree, &mut prefix, &mut paths);
        for path in paths {
            let side = match path.get(1).map(String::as_str) {
                Some("app") => Side::App,
                Some("protocol") => Side::Protocol,
                Some("base") => Side::Base,
                _ => continue,
            };
            map.insert(path.last().unwrap().clone(), side);
        }
    }
    map
}

fn tables_in(text: &str) -> impl Iterator<Item = (&'static str, Side)> + '_ {
    TABLE_OWNERS.iter().copied().filter(move |(table, _)| {
        text.match_indices(table).any(|(at, _)| {
            let before = text[..at].chars().next_back();
            let after = text[at + table.len()..].chars().next();
            let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            !word(before) && !word(after)
        })
    })
}

/// Whether naming `target` from `from` crosses the boundary.
fn crosses(from: Side, target: Side) -> bool {
    target != Side::Base && target != from
}

fn source_crossings() -> BTreeSet<String> {
    let files = production_files();
    let lib = &files.iter().find(|f| f.rel == "lib.rs").unwrap().ast;
    let root = root_reexports(lib);
    let scanned: Vec<(&SourceFile, Names)> = files
        .iter()
        .filter(|f| f.side.is_some())
        .map(|f| (f, scan(&f.ast)))
        .collect();

    // Methods on `SqliteAccountStorage`, by the side that defines them.
    let mut defined: BTreeMap<String, BTreeSet<Side>> = BTreeMap::new();
    for (file, _) in &scanned {
        for item in &file.ast.items {
            let syn::Item::Impl(item_impl) = item else {
                continue;
            };
            if !is_storage_impl(item_impl) || starts_test_only(item_impl.to_token_stream()) {
                continue;
            }
            for impl_item in &item_impl.items {
                if let syn::ImplItem::Fn(f) = impl_item
                    && !is_test_only(&f.attrs)
                {
                    defined
                        .entry(f.sig.ident.to_string())
                        .or_default()
                        .insert(file.side.unwrap());
                }
            }
        }
    }

    let mut found = BTreeSet::new();
    for (file, names) in &scanned {
        let side = file.side.unwrap();
        for literal in &names.literals {
            for (table, owner) in tables_in(literal) {
                if crosses(side, owner) {
                    found.insert(format!("sql {} {table}", file.rel));
                }
            }
        }
        if file.rel != "lib.rs" {
            for path in &names.paths {
                if let Some((target, name)) = path_target(path, &root)
                    && crosses(side, target)
                {
                    found.insert(format!("path {} {name}", file.rel));
                }
            }
        }
        // The app handle carries every app method, so asking for it from
        // protocol or base code is a crossing whatever is called on it next.
        if names.app_handle_calls && matches!(side, Side::Protocol | Side::Base) {
            found.insert(format!("method {} app_storage", file.rel));
        }
        for method in &names.self_calls {
            let Some(sides) = defined.get(method) else {
                continue;
            };
            // A name both sides define is ambiguous; count it as same-side.
            if let [owner] = sides.iter().copied().collect::<Vec<_>>()[..]
                && crosses(side, owner)
            {
                found.insert(format!("method {} {method}", file.rel));
            }
        }
    }
    found
}

struct FreshSchema {
    tables: BTreeSet<String>,
    foreign_keys: Vec<(String, String)>,
    triggers: Vec<(String, String, String)>,
}

fn fresh_schema() -> FreshSchema {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let conn = storage.lock().unwrap();
    let tables: BTreeSet<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut foreign_keys = Vec::new();
    for table in &tables {
        let parents: Vec<String> = conn
            .prepare("SELECT \"table\" FROM pragma_foreign_key_list(?1)")
            .unwrap()
            .query_map([table], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        foreign_keys.extend(parents.into_iter().map(|parent| (table.clone(), parent)));
    }
    let triggers = conn
        .prepare("SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'trigger'")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    FreshSchema {
        tables,
        foreign_keys,
        triggers,
    }
}

fn schema_crossings() -> BTreeSet<String> {
    let schema = fresh_schema();
    let side = |table: &str| owner(table).unwrap_or_else(|| panic!("{table} has no owner"));
    let mut found = BTreeSet::new();
    for (child, parent) in &schema.foreign_keys {
        if side(child) != side(parent) {
            found.insert(format!("fk {child} {parent}"));
        }
    }
    for (name, table, sql) in &schema.triggers {
        let on = side(table);
        if tables_in(sql).any(|(_, other)| other != on && other != Side::Base) {
            found.insert(format!("trigger {table} {name}"));
        }
    }
    found
}

#[test]
fn cfg_predicates_skip_only_test_builds() {
    let skipped = |cfg: &str| {
        let item: syn::ItemFn = syn::parse_str(&format!("#[cfg({cfg})] fn f() {{}}")).unwrap();
        is_test_only(&item.attrs)
    };
    for cfg in [
        "test",
        "all(test, feature = \"x\")",
        "any(test)",
        "not(not(test))",
        "all(unix, test)",
    ] {
        assert!(skipped(cfg), "{cfg} compiles only in test builds");
    }
    for cfg in [
        "not(test)",
        "any(target_os = \"android\", test)",
        "feature = \"x\"",
        "all(not(test), unix)",
        "any(test, feature = \"test-support\")",
    ] {
        assert!(!skipped(cfg), "{cfg} can ship, so it must be scanned");
    }
    let test_fn: syn::ItemFn = syn::parse_str("#[test] fn f() {}").unwrap();
    assert!(is_test_only(&test_fn.attrs));
    let stmt: syn::Stmt =
        syn::parse_str("#[cfg(any(target_os = \"android\", test))] let x = 1;").unwrap();
    assert!(!starts_test_only(stmt.to_token_stream()));
    let stmt: syn::Stmt = syn::parse_str("#[cfg(test)] let x = 1;").unwrap();
    assert!(starts_test_only(stmt.to_token_stream()));
}
