# falco component — host smoke tests

Smoke tests proving `wasm/falco-component.wasm` is callable, reactor-style
(one instantiation, repeated calls), from Python, JS, and Ruby hosts.

Build first:

```sh
make wasm-component       # -> wasm/falco-component.wasm
```

## Exports

The WIT world (`wit/falco.wit`) exports `lint` / `format` / `parse` /
`tokenize` at the **world root**, not nested in an interface. This is a hard
requirement of Ruby's `wasmtime-rb`, whose `get_func(name)` only resolves
root-level exports — an interface-nested export is unreachable. Every host
reaches them by bare name: `get_func("lint")` (Ruby/Python) or
`import { lint }` (jco/JS).

Each function takes `(source, options)` and returns `result<string, string>`:
the `ok` payload is JSON; `err` is an error message. The component has no
filesystem — hosts supply included module sources via `options.includes`, and
the component resolves transitive includes itself, keying diagnostics by module
name. See `docs/wasm-component.md`.

## Python (wasmtime embedding)

```sh
python3 -m venv .venv && .venv/bin/pip install 'wasmtime==46.*'
.venv/bin/python cmd/falco-component/hosts/python/smoke.py \
    wasm/falco-component.wasm cmd/falco-component/testdata/sample.vcl
```

Pin `wasmtime` to match `WASI_ADAPTER_VERSION` in the Makefile (currently
v46.0.0); a newer adapter on an older runtime can fail to instantiate.

## JS (jco transpile, Node)

```sh
cd cmd/falco-component/hosts/js
npm ci
npx jco transpile ../../../../wasm/falco-component.wasm -o dist
node smoke.mjs
```

`jco` maps `result<string, string>` to "return `ok` / throw on `err`" and wires
preview2 WASI imports automatically. `node:wasi` can't consume a component
(preview1 core modules only), so `jco` is the JS path.

## Ruby (wasmtime-rb embedding)

```sh
gem install wasmtime -v '~> 46.0'   # match WASI_ADAPTER_VERSION
```

```ruby
require "wasmtime"
require "json"

engine    = Wasmtime::Engine.new
component = Wasmtime::Component::Component.from_file(engine, "wasm/falco-component.wasm")
linker    = Wasmtime::Component::Linker.new(engine)
Wasmtime::WASI::P2.add_to_linker_sync(linker)
store     = Wasmtime::Store.new(engine, wasi_config: Wasmtime::WasiConfig.new.inherit_stdout.inherit_stderr)
instance  = linker.instantiate(store, component)

lint = instance.get_func("lint")          # store is bound to the func
res  = lint.call(src, "")                  # pass only the args
report = JSON.parse(res.ok) if res.ok?     # res.ok / res.error accessors
```
