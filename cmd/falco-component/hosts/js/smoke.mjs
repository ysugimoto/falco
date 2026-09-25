// Node/jco host smoke test for the falco WASI component.
//
// Imports the jco-transpiled component (one instantiation) and calls `lint`
// and `format` repeatedly on sample VCL strings. jco maps the WIT
// `result<string, string>` to "return the ok string / throw on err", and wires
// the preview2 WASI imports to @bytecodealliance/preview2-shim automatically.
//
// The WIT world exports lint/format/parse/tokenize at the *root* (not nested in
// an interface), so jco surfaces them as top-level named exports.
//
// Usage: node smoke.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { lint, format, parse } from "./dist/falco-component.js";

const here = dirname(fileURLToPath(import.meta.url));
const td = join(here, "..", "..", "testdata");
const clean = readFileSync(join(td, "sample.vcl"), "utf8");
const bad = readFileSync(join(td, "lint-error.vcl"), "utf8");

// --- lint a clean source ---------------------------------------------------
const cleanReport = JSON.parse(lint(clean, ""));
console.log("== lint(clean) summary ==");
console.log(`Errors=${cleanReport.Errors} Warnings=${cleanReport.Warnings} Infos=${cleanReport.Infos}`);

// --- lint a source with diagnostics (same instance) ------------------------
const badReport = JSON.parse(lint(bad, ""));
console.log("\n== lint(bad) LintErrors (native lint -json shape) ==");
for (const [file, errs] of Object.entries(badReport.LintErrors)) {
  for (const e of errs) {
    console.log(`  [${e.Severity}] ${file}:${e.Token.Line}:${e.Token.Position} ${e.Message}`);
    if (e.Reference) console.log(`     ref: ${e.Reference}`);
  }
}
console.log(`  totals: Errors=${badReport.Errors} Warnings=${badReport.Warnings} Infos=${badReport.Infos}`);

// --- format with config (same instance, repeated call) ---------------------
console.log("\n== format(clean, tab indent) ==");
console.log(format(clean, JSON.stringify({ indentStyle: "tab" })));

// --- error path: parse maps result err -> thrown exception -----------------
console.log("== error path (parse of invalid VCL throws) ==");
try {
  parse("sub vcl_recv { this is not valid");
  console.log("  ERROR: expected a throw");
  process.exit(1);
} catch (e) {
  console.log(`  threw as expected: ${String(e).slice(0, 80)}`);
}

// --- multi-file lint with a nested include --------------------------------
// The component has no filesystem, so the host supplies include contents via
// options.includes. Transitive includes are discovered by the component (main
// -> mod_a -> mod_b); diagnostics are keyed by the real module name, not the
// synthetic "input.vcl".
console.log("\n== lint with nested includes (main -> mod_a -> mod_b) ==");
const incMain = `include "mod_a";\n\nsub vcl_recv {\n#FASTLY RECV\n  set req.http.X-Main = "1";\n}\n`;
const incModA = `include "mod_b";\n\nsub vcl_deliver {\n#FASTLY DELIVER\n  set resp.http.X-A = "a";\n}\n`;
// mod_b (the deepest, transitively-included module) carries the lint error.
const incModB = `sub vcl_fetch {\n#FASTLY FETCH\n  set bereq.http.X-Bad = undefined.variable;\n}\n`;
const incReport = JSON.parse(
  lint(incMain, JSON.stringify({ includes: { mod_a: incModA, mod_b: incModB } })),
);
const incKeys = Object.keys(incReport.LintErrors);
console.log(`  LintErrors keys: ${JSON.stringify(incKeys)} totals: Errors=${incReport.Errors}`);
for (const [file, errs] of Object.entries(incReport.LintErrors)) {
  for (const e of errs) {
    console.log(`  [${e.Severity}] ${file}:${e.Token.Line}:${e.Token.Position} ${e.Message} (Token.File=${e.Token.File})`);
  }
}
// Assert the transitive include resolved and is keyed by its real module name.
if (!incKeys.includes("mod_b")) {
  throw new Error(`expected LintErrors keyed by "mod_b", got ${JSON.stringify(incKeys)}`);
}
if (incReport.LintErrors.mod_b.some((e) => e.Token.File !== "mod_b")) {
  throw new Error("expected every mod_b error to carry Token.File == 'mod_b'");
}
if (incReport.Errors < 1) throw new Error("expected at least one error from the included module");
// A bare include with no contents supplied must report an unresolved-include
// error (not crash) -- the single-file path stays intact.
const missing = JSON.parse(lint(`include "absent";\nsub vcl_recv {\n#FASTLY RECV\n}\n`, ""));
if (missing.Errors < 1) throw new Error("expected an unresolved-include error when no contents supplied");
console.log(`  unresolved include (no contents) -> Errors=${missing.Errors} (reported, not crashed)`);

// --- stress: prove the reactor is durably reusable ------------------------
// Regression for the preview1 adapter-State corruption that crashed the
// instance after a few non-trivial calls (resetArena used to rewind the bump
// arena over the adapter's persistent State). One instantiation must survive
// many large format+lint calls interleaved with small ones.
function buildLargeVCL(minBytes) {
  let s = "sub vcl_recv {\n#FASTLY RECV\n";
  for (let i = 0; s.length < minBytes; i++) {
    s += `  set req.http.X-Hdr-${i} = "value-${i}-aaaaaaaaaaaaaaaaaaaa";\n`;
    s += `  if (req.url ~ "^/path-${i}/segment") {\n    set req.http.X-Match-${i} = "1";\n  }\n`;
  }
  return s + "}\n";
}
const large = buildLargeVCL(100 * 1024);
console.log(`\n== stress: ${Math.floor(large.length / 1024)} KiB VCL, repeated format+lint in one instance ==`);
let stressCalls = 0;
for (let i = 0; i < 6; i++) {
  if (format(large, "").length === 0) throw new Error("stress: empty format output");
  if (JSON.parse(lint(large, "")).Errors !== 0) throw new Error("stress: unexpected lint errors on clean large VCL");
  // Interleave a small input so the arena high-water mark swings widely.
  format(clean, "");
  JSON.parse(lint(clean, ""));
  stressCalls += 4;
}
console.log(`  survived ${stressCalls} calls (6 large format+lint pairs + small mix), no crash`);

console.log("\nOK: lint + format + parse called repeatedly from one jco instantiation");
