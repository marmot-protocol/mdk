#!/usr/bin/env bun

// Compares the public API surface of mdk-core against mdk-uniffi bindings.
// Reads rustdoc JSON output (generated with nightly + --output-format json)
// and reports methods that exist in core but are not bound in uniffi.
//
// Usage:
//   bun scripts/check-uniffi-bindings.ts [--core PATH] [--uniffi PATH] [--allowlist PATH]
//
// Defaults:
//   --core     target/doc/mdk_core.json
//   --uniffi   target/doc/mdk_uniffi.json
//   --allowlist crates/mdk-uniffi/unbound-methods.txt

import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve } from "path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type BindingStatus = "bound" | "unbound" | "allowlisted";

interface MethodInfo {
  name: string;
  file: string;
  line: number;
}

interface ClassifiedMethod extends MethodInfo {
  status: BindingStatus;
  reason?: string;
}

interface RustdocItem {
  name: string;
  visibility: string;
  inner: Record<string, unknown>;
  span?: { filename: string; begin: [number, number] };
}

interface RustdocData {
  root: number;
  index: Record<string, RustdocItem>;
}

interface Options {
  core: string;
  uniffi: string;
  allowlist: string;
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function parseArgs(): Options {
  const args = process.argv.slice(2);
  const opts: Options = {
    core: "target/doc/mdk_core.json",
    uniffi: "target/doc/mdk_uniffi.json",
    allowlist: "crates/mdk-uniffi/unbound-methods.txt",
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--core" && args[i + 1]) opts.core = args[++i];
    else if (args[i] === "--uniffi" && args[i + 1]) opts.uniffi = args[++i];
    else if (args[i] === "--allowlist" && args[i + 1])
      opts.allowlist = args[++i];
  }
  return opts;
}

// ---------------------------------------------------------------------------
// Allowlist parsing
// ---------------------------------------------------------------------------

function loadAllowlist(path: string): Map<string, string> {
  if (!existsSync(path)) return new Map();
  const lines = readFileSync(path, "utf-8").split("\n");
  const entries = new Map<string, string>();
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [name, ...rest] = line.split("#");
    const method = name.trim();
    const reason = rest.join("#").trim() || "no reason given";
    if (method) entries.set(method, reason);
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Rustdoc JSON extraction helpers
// ---------------------------------------------------------------------------

/** Extract all public methods from inherent impl blocks of a named struct. */
function extractStructMethods(
  index: Record<string, RustdocItem>,
  structName: string,
): MethodInfo[] {
  const structEntry = Object.values(index).find(
    (item) => item.name === structName && item.inner?.struct,
  );
  if (!structEntry) return [];

  const structInner = structEntry.inner.struct as {
    impls?: number[];
  };
  const implIds = structInner.impls ?? [];
  const methods: MethodInfo[] = [];

  for (const implId of implIds) {
    const impl = index[String(implId)];
    if (!impl?.inner?.impl) continue;
    const implData = impl.inner.impl as {
      trait?: unknown;
      items?: number[];
    };
    // Skip trait impls (From, Debug, etc.)
    if (implData.trait) continue;

    for (const itemId of implData.items ?? []) {
      const item = index[String(itemId)];
      if (!item) continue;
      if (item.visibility !== "public") continue;
      if (!item.inner?.function) continue;
      methods.push({
        name: item.name,
        file: item.span?.filename ?? "unknown",
        line: item.span?.begin?.[0] ?? 0,
      });
    }
  }

  return methods;
}

/** Extract all public free functions from a specific source file pattern. */
function extractFreeFunctions(
  index: Record<string, RustdocItem>,
  filePattern: string,
): MethodInfo[] {
  return Object.values(index)
    .filter(
      (item) =>
        item.visibility === "public" &&
        item.inner?.function &&
        item.span?.filename?.includes(filePattern),
    )
    .map((item) => ({
      name: item.name,
      file: item.span?.filename ?? "unknown",
      line: item.span?.begin?.[0] ?? 0,
    }));
}

/** Extract all public free functions exported from the crate root module. */
function extractRootFreeFunctions(data: RustdocData): string[] {
  const rootId = String(data.root);
  const root = data.index[rootId];
  const moduleInner = root?.inner?.module as { items?: number[] } | undefined;
  if (!moduleInner) return [];

  return (moduleInner.items ?? [])
    .map((id) => data.index[String(id)])
    .filter((item) => item?.visibility === "public" && item?.inner?.function)
    .map((item) => item.name);
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

function classify(
  items: MethodInfo[],
  boundNames: Set<string>,
  allowlist: Map<string, string>,
): ClassifiedMethod[] {
  return items.map((item) => {
    if (allowlist.has(item.name)) {
      return { ...item, status: "allowlisted" as const, reason: allowlist.get(item.name) };
    }
    if (boundNames.has(item.name)) {
      return { ...item, status: "bound" as const };
    }
    return { ...item, status: "unbound" as const };
  });
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

function buildReport(
  unboundItems: ClassifiedMethod[],
  boundItems: ClassifiedMethod[],
  allowlistedItems: ClassifiedMethod[],
  totalBindable: number,
  coveragePct: string,
): string {
  let md = "";

  md += "## UniFFI Binding Coverage\n\n";
  md += `**${unboundItems.length} public method(s) not bound in UniFFI**\n\n`;
  md += `Coverage: ${boundItems.length}/${totalBindable} bindable methods (${coveragePct}%)\n\n`;

  // Unbound first — these are the actionable ones
  md += "### ⚠️ Not Bound\n\n";
  md += "| Method | Source |\n";
  md += "|--------|--------|\n";
  for (const item of unboundItems) {
    md += `| \`${item.name}\` | \`${item.file}:${item.line}\` |\n`;
  }

  // Bound — collapsed
  md += `\n<details>\n<summary>✅ Bound methods (${boundItems.length})</summary>\n\n`;
  md += "| Method | Source |\n";
  md += "|--------|--------|\n";
  for (const item of boundItems) {
    md += `| \`${item.name}\` | \`${item.file}:${item.line}\` |\n`;
  }
  md += "\n</details>\n";

  // Allowlisted — collapsed
  if (allowlistedItems.length > 0) {
    md += `\n<details>\n<summary>➖ Intentionally excluded (${allowlistedItems.length})</summary>\n\n`;
    md += "| Method | Reason |\n";
    md += "|--------|--------|\n";
    for (const item of allowlistedItems) {
      md += `| \`${item.name}\` | ${item.reason} |\n`;
    }
    md += "\n</details>\n";
  }

  return md;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const opts = parseArgs();

// Load rustdoc JSON files
let coreData: RustdocData;
let uniffiData: RustdocData;
try {
  coreData = JSON.parse(readFileSync(resolve(opts.core), "utf-8"));
} catch (e) {
  console.error(`Failed to read core rustdoc JSON: ${opts.core}`);
  console.error((e as Error).message);
  process.exit(1);
}
try {
  uniffiData = JSON.parse(readFileSync(resolve(opts.uniffi), "utf-8"));
} catch (e) {
  console.error(`Failed to read uniffi rustdoc JSON: ${opts.uniffi}`);
  console.error((e as Error).message);
  process.exit(1);
}

const allowlist = loadAllowlist(resolve(opts.allowlist));

// Extract core public API
const coreMethods = extractStructMethods(coreData.index, "MDK");
const coreFreeFns = extractFreeFunctions(coreData.index, "group_image");

// Extract uniffi bound API
const uniffiMethodNames = new Set(
  extractStructMethods(uniffiData.index, "Mdk").map((m) => m.name),
);
const uniffiFreeFnNames = new Set(extractRootFreeFunctions(uniffiData));

// Classify
const methodReport = classify(coreMethods, uniffiMethodNames, allowlist);
const freeFnReport = classify(coreFreeFns, uniffiFreeFnNames, allowlist);

// Compute stats
const allItems = [...methodReport, ...freeFnReport];
const allSorted = allItems.sort((a, b) => a.name.localeCompare(b.name));

const unboundItems = allSorted.filter((i) => i.status === "unbound");
const boundItems = allSorted.filter((i) => i.status === "bound");
const allowlistedItems = allSorted.filter((i) => i.status === "allowlisted");

const totalBindable = allItems.length - allowlistedItems.length;
const coveragePct =
  totalBindable > 0
    ? ((boundItems.length / totalBindable) * 100).toFixed(1)
    : "100.0";

// All covered: silent success
if (unboundItems.length === 0) {
  process.exit(0);
}

// Emit GitHub Actions annotations for unbound methods
for (const item of unboundItems) {
  console.log(
    `::warning file=${item.file},line=${item.line}::${item.name}() is a public method in mdk-core but is not bound in mdk-uniffi`,
  );
}

// Write PR comment body
const md = buildReport(
  unboundItems,
  boundItems,
  allowlistedItems,
  totalBindable,
  coveragePct,
);
const commentPath =
  process.env.UNIFFI_COMMENT_PATH || "/tmp/uniffi-check-comment.md";
writeFileSync(commentPath, md);

// Console summary
console.log(
  `UniFFI binding coverage: ${boundItems.length}/${totalBindable} (${coveragePct}%)`,
);
console.log(
  `  Bound: ${boundItems.length}, Unbound: ${unboundItems.length}, Allowlisted: ${allowlistedItems.length}`,
);
console.log("\nUnbound methods:");
for (const item of unboundItems) {
  console.log(`  - ${item.name} (${item.file}:${item.line})`);
}

// Always exit 0 — this check is informational only
process.exit(0);
