#!/usr/bin/env python3
"""Python wasmtime host smoke test for the falco WASI component.

Loads wasm/falco-component.wasm, instantiates it once (reactor style), and calls
the `lint` and `format` exports repeatedly on a sample VCL string -- no temp
files, no stdout capture, no per-call re-instantiation.

Usage:
    python smoke.py <component.wasm> <sample.vcl>
"""
import json
import sys

from wasmtime import Engine, Store, WasiConfig
from wasmtime.component import Component, Linker


def main() -> int:
    component_path, vcl_path = sys.argv[1], sys.argv[2]
    with open(vcl_path, encoding="utf-8") as f:
        source = f.read()

    engine = Engine()
    store = Store(engine)
    # The component imports preview2 wasi:cli/* (from the adapter); satisfy them.
    wasi = WasiConfig()
    wasi.inherit_stdout()
    wasi.inherit_stderr()
    store.set_wasi(wasi)

    component = Component.from_file(engine, component_path)
    linker = Linker(engine)
    linker.add_wasip2()
    instance = linker.instantiate(store, component)

    # The world exports lint/format/parse/tokenize at the root, so they resolve
    # as top-level world exports (no interface sub-instance to descend into).
    def get(name):
        idx = instance.get_export_index(store, name)
        assert idx is not None, f"missing function {name}"
        fn = instance.get_func(store, idx)
        assert fn is not None, f"{name} is not a function"
        return fn

    lint, fmt = get("lint"), get("format")

    # --- call 1: lint -------------------------------------------------------
    res = lint(store, source, "")
    if res.tag != "ok":
        print("lint failed:", res.payload, file=sys.stderr)
        return 1
    report = json.loads(res.payload)
    print("== lint (RunnerResult JSON) ==")
    print(json.dumps(report, indent=2)[:800])
    print(f"\nlint summary: Errors={report['Errors']} "
          f"Warnings={report['Warnings']} Infos={report['Infos']}")

    # --- call 2: format (same instance, no re-instantiation) ---------------
    res = fmt(store, source, json.dumps({"indentWidth": 4, "indentStyle": "space"}))
    if res.tag != "ok":
        print("format failed:", res.payload, file=sys.stderr)
        return 1
    print("\n== format (4-space indent) ==")
    print(res.payload)

    # --- call 3: format again with different config, proving reuse ----------
    res = fmt(store, source, "")
    assert res.tag == "ok"
    print("== format (defaults, reused instance) -- first line ==")
    print(res.payload.splitlines()[0] if res.payload else "(empty)")

    # --- stress: prove the reactor is durably reusable ---------------------
    # Regression for the preview1 adapter-State corruption that crashed the
    # instance after a few non-trivial calls (resetArena used to rewind the
    # bump arena over the adapter's persistent State). One instantiation must
    # survive many large format+lint calls interleaved with small ones.
    def build_large_vcl(min_bytes: int) -> str:
        parts = ["sub vcl_recv {\n#FASTLY RECV\n"]
        total, i = len(parts[0]), 0
        while total < min_bytes:
            chunk = (f'  set req.http.X-Hdr-{i} = "value-{i}-aaaaaaaaaaaaaaaaaaaa";\n'
                     f'  if (req.url ~ "^/path-{i}/segment") {{\n'
                     f'    set req.http.X-Match-{i} = "1";\n  }}\n')
            parts.append(chunk)
            total += len(chunk)
            i += 1
        parts.append("}\n")
        return "".join(parts)

    large = build_large_vcl(100 * 1024)
    print(f"\n== stress: {len(large) // 1024} KiB VCL, repeated format+lint in one instance ==")
    stress_calls = 0
    for _ in range(6):
        f = fmt(store, large, "")
        assert f.tag == "ok" and f.payload, "stress: format failed on large VCL"
        r = lint(store, large, "")
        assert r.tag == "ok" and json.loads(r.payload)["Errors"] == 0, "stress: lint failed on clean large VCL"
        # Interleave a small input so the arena high-water mark swings widely.
        assert fmt(store, source, "").tag == "ok"
        assert lint(store, source, "").tag == "ok"
        stress_calls += 4
    print(f"  survived {stress_calls} calls (6 large format+lint pairs + small mix), no crash")

    print("\nOK: lint + format called repeatedly from one instantiation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
