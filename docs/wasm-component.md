# A WIT / Component-Model build of falco (lint + format)

Status: **supported build target.** This ships a real feature: a
`make wasm-component` target, a stable WIT contract (`wit/falco.wit`), three host
smoke tests, canonical-ABI unit tests, and the reference documentation below. It
documents how falco ships as a single WebAssembly **component** with one WIT
interface consumed by many hosts.

## Host requirements (read before embedding)

The canonical-ABI glue (`cmd/falco-component/abi.go`) relies on a single,
synchronously-read return area and shared package-level state. Hosts MUST:

- **Lift each result synchronously**, before issuing the next export call. There
  is no `cabi_post`; the next call's `lowerResult` overwrites the return area and
  the payload's backing string. A host that pipelines or defers the copy reads
  corrupted bytes.
- **Not share one instance across threads.** The reactor is single-threaded and
  its arena/return-area globals are unsynchronized (no wasi-threads).
- **Be prepared to re-instantiate** on a trap. Oversized input can exhaust the
  16 MiB arena during the host's argument lowering, which traps the instance for
  every subsequent call (see the `arenaSize` doc in `abi.go`).

These also depend on Go's current non-moving GC (the return-area pointer is not
relocated between an export's return and the host's lift); a future moving
collector would break this.

## Parse-error signal matrix

The JSON *shape* of a `lint` result is identical across both remaining builds
(native and the component), but the out-of-band signal for a
JSON-mode parse error differs by design — do not assume parity:

| Build              | JSON-mode parse error signal                      |
| ------------------ | ------------------------------------------------- |
| native `falco`     | exit 0 (parse errors do not increment `Errors`)   |
| component (`lint`) | `ok` payload with `ParseErrors` populated; no exit |

In every case the `ParseErrors` map carries the diagnostic, so a consumer that
parses the payload sees the same data.


## TL;DR recommendation

Build the component from **standard Go** (`GOOS=wasip1 GOARCH=wasm`,
`-buildmode=c-shared` reactor) plus **`wasm-tools component new`** with the
`wasi_snapshot_preview1` reactor adapter. Hand-write the canonical-ABI glue
(`cmd/falco-component/abi.go`); do **not** use TinyGo and do **not** rely on
`wit-bindgen-go`'s generated wrappers.

This produces a working, validated component (`wasm/falco-component.wasm`,
~9.5 MB — comparable to the 9 MB `falco.wasm`) in the `falco` world
exporting `lint`, `format`, `parse`, `tokenize` as **world-root** functions. It
is proven callable, reactor-style (one instantiation, repeated calls, no temp
files, no stdout capture), from three hosts:

- **Python `wasmtime`** embedding (`cmd/falco-component/hosts/python/smoke.py`)
- **JS via `jco transpile`** on Node (`cmd/falco-component/hosts/js/smoke.mjs`)
- **Ruby `wasmtime` gem** (wasmtime-rb), the host that requires the root-export
  shape — see *WIT design* below

`make wasm-component` builds it. The existing `wasm` (js) build
is untouched.

## Why not the other paths — the deciding evidence

The brief proposed two turn-key paths. **Both are blocked today**, so the
viable route is standard Go with hand-rolled ABI glue.

### TinyGo + wit-bindgen-go: cannot compile falco

Empirically attempted (`tinygo 0.41.1`, `tinygo build -target=wasip1 ./cmd/falco-component`):

```
linter/types/types.go:23:25: cannot use 0x000000100000000 (untyped int
  constant 4294967296) as Type value in constant declaration (overflows)
... (continues for StringType .. RegexType)
```

`linter/types` defines `type Type int` with bit-flag constants up to
`0x100000000100000` (≈ 7.2e16). Standard Go's `GOARCH=wasm` uses a **64-bit
`int`**, so these compile. **TinyGo's wasm `int` is 32-bit**, so every constant
above `2^32` overflows at compile time. This is a structural dependency on
64-bit `int` across the linter's type system; supporting TinyGo would require
changing `Type` to `uint64` and auditing all usages — a core change made solely
to satisfy a toolchain.

And that is only the *first* blocker. falco's regex support comes from
`go.elara.ws/pcre` (replaced by `github.com/dip-proto/go-pcre`), whose non-JS
build tag routes through `modernc.org/libc` — which TinyGo also does not
support. The 64-bit-`int` failure halts the build before pcre is even reached.

> TinyGo's `wasip2` target reports `GOOS=linux GOARCH=arm` (a TinyGo quirk), so
> a `//go:build wasip1 && wasm` constraint excludes all files under it. Use
> `-target=wasip1` to actually exercise compilation.

### Standard Go + wit-bindgen-go: cannot emit the `result<>` cabi

`wit-bindgen-go v0.7.0` generates cabi wrappers that **return `*cm.Result[...]`**.
Standard Go's `//go:wasmexport` rejects pointer-to-struct results:

```
gen/.../vcl.wasm.go:13:6: go:wasmexport: unsupported result type
  *cm.Result[string,string,string]
```

And even setting that aside, `wit-bindgen-go`'s own README warns:

> Package `cm` and generated bindings ... may have compatibility issues with the
> Go garbage collector ... In Go (but not TinyGo), the GC may detect ... a
> non-pointer value in an area it expects to see a pointer. This is an area of
> active development.

So `wit-bindgen-go` targets TinyGo; its standard-Go support for `variant`/
`result` types is not production-ready.

### The viable path: standard Go + hand-rolled canonical ABI

Standard Go compiles **all** of falco for `wasip1` in <1s (the component
build itself does). And `//go:wasmexport` + `-buildmode=c-shared`
produces a valid reactor. The only gap is the canonical-ABI lift/lower for
strings and `result<string, string>`. We hand-write it in
`cmd/falco-component/abi.go`:

- Export `cabi_realloc`, plus `lint`, `format`, `parse`, `tokenize` under their
  bare (world-root) names.
- Each export takes `(ptr, len)` `uint32` pairs (the canonical lowering of
  `string` params) and returns a `uint32` offset to a 12-byte return area
  (`result<string,string>` = variant of two strings). `uint32` is a permitted
  `//go:wasmexport` result type, sidestepping the pointer-return restriction.
- We never touch `cm.Result`, so the GC variant/result issue does not apply.

## Architecture / build pipeline

```
cmd/falco-component/        (//go:build wasip1 && wasm)
  main.go   – do{Lint,Format,Parse,Tokenize}: in-memory, string-in, JSON-out
  abi.go    – hand-rolled canonical-ABI glue (cabi_realloc + 4 wasmexports)
  testdata/ – sample.vcl, lint-error.vcl
  hosts/    – python/, js/, and ruby smoke tests (see hosts/README.md)
wit/falco.wit               – the WIT contract (world `falco`, root func exports)
```

```
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o falco-core.wasm ./cmd/falco-component
wasm-tools component embed wit --world falco falco-core.wasm -o falco-embedded.wasm
wasm-tools component new  falco-embedded.wasm \
    --adapt wasi_snapshot_preview1=wasi_snapshot_preview1.reactor.wasm \
    -o wasm/falco-component.wasm
wasm-tools validate --features component-model wasm/falco-component.wasm
```

`make wasm-component` runs exactly this and auto-downloads the preview1 reactor
adapter (matching the `wasmtime` release) if absent.

## WIT design

See `wit/falco.wit`. All four functions are exported at the **world root**
(directly under `world falco`, not nested inside an interface) and are
string-in / string-out:

```wit
world falco {
    export lint:     func(source: string, options: string) -> result<string, string>;
    export format:   func(source: string, config:  string) -> result<string, string>;
    export parse:    func(source: string)                  -> result<string, string>;
    export tokenize: func(source: string)                  -> result<string, string>;
}
```

### Why root exports, not an interface

The functions originally lived inside an exported `vcl` interface
(`export vcl;`), surfacing as the interface-qualified core export
`falco:tools/vcl@0.1.0#lint` etc. That works for jco and the Python `wasmtime`
embedding, but it is **unreachable from the Ruby `wasmtime` gem**
(observed on wasmtime-rb 45; unchanged on 46.x). wasmtime-rb's `Wasmtime::Component::Instance` exposes only
`get_func(name)` (arity 1), which resolves **root-level world exports only** and
provides **no** export-index / sub-instance accessor to descend into an exported
interface instance. Every name variant (`"falco:tools/vcl@0.1.0#lint"`,
`"falco:tools/vcl#lint"`, `"lint"`, …) returned `nil`.

Moving the four functions to world-root exports makes a bare
`get_func("lint")` resolve in wasmtime-rb, while jco and Python keep working:
world-root func exports surface as top-level named exports in jco
(`import { lint } from "./component.js"`) and as top-level world exports in
Python (`instance.get_export_index(store, "lint")`). The corresponding
`//go:wasmexport` directives in `abi.go` use the bare core names (`lint`,
`format`, `parse`, `tokenize`) that `wasm-tools component embed/new` expects for
world-level func exports.

**`result<_, string>`-wrapped JSON string** (the chosen encoding) was selected
over native WIT records because it guarantees **zero shape drift**: `lint`'s
`ok` payload is the *same* `RunnerResult` JSON that `falco lint -json` emits
(`Infos`/`Warnings`/`Errors`, `LintErrors`/`ParseErrors` keyed by file, each
error carrying `Severity`, `Message`, `Reference`, `Token.{Line,Position,File}`,
`Rule`). The Go side reuses the real `linter.LintError` / `parser.ParseError`
types, so the JSON is byte-shape-identical by construction — downstream
consumers of the documented contract parse it unchanged. Host bindings map the
WIT `result` idiomatically: Python returns a `Variant(tag, payload)`; jco
returns the `ok` string or **throws** on `err`; Ruby returns a
`Wasmtime::Component::Result` with `ok?`/`ok` and `error?`/`error` accessors
(`ok` is the success payload string, `error` the failure message). Note that
wasmtime-rb binds the `Store` when you obtain the func, so you call
`func.call(arg1, arg2)` with no store argument.

`parse`/`tokenize` are included (the JS build has them; the WASI command build
does not) because the JSON-string encoding makes them nearly free.

### Config reuse with no filesystem

The component has no filesystem, so options are passed as JSON strings (pass
`""` for defaults), not via `config.New`/`.falco.yaml`:

- `lint` options: `{ "scope", "rules": {"<rule>":"ERROR|WARNING|INFO|IGNORE"},
  "includes": {"<module>":"<source>"}, "includePaths": ["<prefix>", ...] }`.
  Severity overrides reuse the same case-insensitive mapping as
  `cmd/falco`. An unrecognized `scope` is rejected with `err`.
- `format` config: the `FormatConfig` fields (`indentWidth`, `indentStyle`,
  `explicitStringConcat`, `breakCompoundConditions`, `indentCaseLabels`, …),
  same field names the `cmd/wasm` JS build accepts.

### Include / module resolution

`include` statements resolve against the host-supplied `options.includes` map
(module-name → source), via `resolver.MapResolver` (a generalization of
`resolver.StaticResolver`). The component has no filesystem, so the host (e.g. a
VS Code LSP server, which has filesystem and open-document access) supplies the
module sources up front; `MapResolver.Resolve` mirrors `FileResolver`'s search
semantics (optional `.vcl` suffix, each `includePaths` entry tried as a prefix).

**Transitive-include discovery is the component's job, not the host's.** The
linter recurses through every `include` it parses, calling `Resolve` for each
(including nested ones), so the host need only supply the *full set of reachable
module contents* — it does not compute the include graph or ordering. A module
whose source is missing from the map produces an in-band unresolved-include lint
error (it does not trap), so omitting `includes` entirely keeps the single-file
path byte-shape-identical to before.

`LintErrors`/`ParseErrors` are keyed by — and each `Token.File` carries — the
**real module name** (the matched `includes` key); diagnostics in the top-level
source keep the synthetic `input.vcl` key.

#### Why a content-map, not a WIT import callback

The alternative — adding `import resolve-include: func(name) ->
result<string,string>` to world `falco` and resolving lazily — is cleaner and
fetches only what's needed, but **wasmtime-rb cannot supply a component import
function**: its `Wasmtime::Component::LinkerInstance` exposes only `instance`
and `module` (no `add_func`/`func_new`), so a host-defined import of
`func(string) -> result<string,string>` is unimplementable from Ruby. (jco can
supply imports, and wasmtime-py's `LinkerInstance` does have `add_func`, but the
Ruby gap is decisive — Ruby is the same host that forced the world-root export
shape above.) The content-map design also needs **no ABI/WIT signature change**
and no import-side canonical-ABI glue in `abi.go`. The cost is that the entire
include closure travels in one `lint` call's `options` argument; see the arena
cap note under *Risks / limitations* (≈ 8 MiB combined source ceiling).

## Host consumption

Exact commands and observed output are in
`cmd/falco-component/hosts/README.md`. All three call `lint` and `format` on the
same instance repeatedly. jco is the documented JS path; **`node:wasi` is not
viable** for a component — it implements preview1 *core modules* only and cannot
instantiate a component.

## Risks / limitations

- **Toolchain maturity.** The clean turn-key paths (TinyGo, `wit-bindgen-go`
  standard-Go) don't work for falco today. We depend on hand-written ABI glue;
  if the WIT grows richer types (records, lists, resources) the hand-rolled
  lift/lower grows too. Re-evaluate `wit-bindgen-go` standard-Go support as it
  matures.
- **`cabi_realloc` must avoid the Go heap.** The preview1→preview2 adapter calls
  `cabi_realloc` **re-entrantly during `_initialize`** (on the runtime system
  stack, g0). A Go heap allocation there trips `runtime.badsystemstack` and
  crashes. `abi.go` backs `cabi_realloc` with a fixed **16 MiB static bump
  arena** instead — which also caps a single call's combined argument size at
  16 MiB. Oversized input returns a null allocation (a canonical-ABI trap). Bump
  the constant if larger inputs are needed. **Note for include resolution:**
  `lint`'s `options.includes` bundles the *entire* multi-file project (main +
  all reachable modules), JSON-escaped, into one call's `options` string, so the
  cap bounds the whole closure, not one file. The host's string lowering can
  transiently double its buffer, so the practical ceiling is ≈ 8 MiB of combined
  escaped source per `lint` — ample for the LSP use case (a service's full VCL
  closure is typically well under a megabyte); raise `arenaSize` (BSS, zero file
  cost) for larger workspaces.
- **Reactor durability: the arena reset must preserve the adapter's `State`.**
  This was a real bug. The component is a *reactor* (instantiate once, call
  repeatedly), but it used to crash after a few non-trivial `format`/`lint`
  calls in one instantiation. The failure was always inside the preview1 adapter
  — `assertion failed at adapter line 2857` → `RuntimeError: unreachable` in
  `wasi_snapshot_preview1::macros::assert_fail`, reached from `clock_time_get`
  (and `poll_oneoff`) — not in falco code, and reproduced identically from
  wasmtime and jco hosts. Consumption scaled with *input size × calls*, not pure
  call count.

  **Root cause (verified by reading the adapter, not by guessing):** the
  resource exhausted was **not** the Go heap and **not** cumulative adapter-arena
  growth. The adapter lazily allocates a ~64 KiB `State` struct (with a magic
  canary `0x216F4F35` at its head and tail) by calling
  `__main_module__.cabi_realloc` — i.e. **our** static bump arena — on the first
  preview1 import, and caches a raw pointer to it, re-validating the canary on
  every later `clock_time_get`/`poll_oneoff`. The old `resetArena()` rewound the
  bump pointer to `0` after every export call, reclaiming the region holding
  that persistent `State`. The next call's host-lowered input (written from
  offset 0) overwrote the `State`, corrupting the canary, so the next clock
  import tripped the adapter's assertion and trapped the whole instance. (The
  prior `abi.go` comment explicitly assumed "no import retains a pointer into
  that region across calls" — that assumption was wrong: the adapter's `State`
  does.)

  **Fix (chosen over the alternatives below):** `resolveReset`/`resetArena` now
  latch a **floor** at the first call's high-water mark (which by then covers the
  adapter's `State` plus that call's inputs) and rewind only to the floor on
  every subsequent call. `State` is the adapter's *only* persistent
  `cabi_realloc` allocation, so the floor never needs to grow. **Trade-off:** the
  first call's input bytes are never reclaimed — a one-time leak bounded by a
  single input's size (≤ a few MiB), negligible against the 16 MiB arena. The
  pure `resolveReset` is unit-tested off-target in `abi_test.go`; both host smoke
  tests gained a stress case (≥ 100 KiB VCL formatted+linted ≥ 5× plus a
  large/small mix in one instantiation).

  **Alternatives rejected.** (1) *TinyGo core* (the ideal — no preview1 adapter,
  so the whole bug class disappears, and a far smaller artifact) remains blocked:
  `modernc.org/memory` (under pcre → `modernc.org/libc`) selects
  `mmap_linux_32.go`/`mmap_unix.go` on TinyGo's `wasip2` target and needs
  `syscall.SYS_MMAP2`/`SYS_MUNMAP`, which TinyGo's wasm syscall layer does not
  provide; standard Go `wasip1` instead compiles `memory.go`'s pure-Go fallback.
  `linter/types` also overflows TinyGo's 32-bit `int` (see *Why not the other
  paths*). (2) *Native `GOOS=wasip2`* on Go 1.25 still emits a `wasip1` core that
  needs the adapter, so it would not avoid the adapter `State` either. The
  adapter is already the newest release (v46.0.0); a version bump does not help.
- **No `cabi_post`.** The return area is a static buffer the host reads
  synchronously; we export no `cabi_post_*`, so there is no per-call free (and
  no leak — the buffer is reused). Fine for a single-threaded reactor.
- **`go vet` cosmetic warning.** `abi.go` triggers `possible misuse of
  unsafe.Pointer` (the `uintptr(unsafe.Pointer(...))` ABI pattern). It is safe
  here (Go's wasm GC is non-moving; globals keep payloads alive) and does **not**
  affect `make lint`, since the `wasip1 && wasm` build tag excludes the package
  from host-platform linting.
- **Binary size.** ~9.5 MB, in line with `falco.wasm` (9 MB). No regression,
  but not small.
- **`wasmtime-go` lag.** Not used here (the Go *host* embedding for components
  has historically lagged); the wasmtime *Python* and *Rust* embeddings and jco
  are the mature consumers. The Go side is the *guest*, not a host.
- **pcre on TinyGo.** Moot given the earlier 64-bit-`int` blocker, but recorded:
  `modernc.org/libc` (the pcre backend for non-JS targets) is unsupported by
  TinyGo, so even fixing `linter/types` would not unblock TinyGo.

## Coexistence

`cmd/wasm` (js) and its build are
unchanged and still build. The component lives in a new `cmd/falco-component`
package (build-tagged `wasip1 && wasm`, excluded from native `go build ./...`)
with its own `make wasm-component` target. `go.mod` is unchanged (the temporary
`go.bytecodealliance.org/cm` dependency was removed once the generated bindings
were dropped in favor of hand-rolled glue).
