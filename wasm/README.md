# Falco Wasm

WebAssembly build of Falco for web browsers.

## API

```js
// Parse VCL to AST
FalcoVCL.parse(vcl: string): { ast?: object, error?: string }

// Tokenize VCL
FalcoVCL.tokenize(vcl: string): { tokens?: Token[], error?: string }

// Format VCL
FalcoVCL.format(vcl: string, options?: FormatOptions): { formatted?: string, error?: string }

// Lint VCL
FalcoVCL.lint(vcl: string, options?: LintOptions): { errors?: LintError[], error?: string }
```

## Limitations

**Regex validation**: The native Falco CLI uses PCRE for regex validation, but PCRE's native code cannot run in WebAssembly. The Wasm build uses Go's standard `regexp` package instead, which lacks support for some PCRE features:

- Lookahead (`(?=...)`, `(?!...)`)
- Lookbehind (`(?<=...)`, `(?<!...)`)
- Atomic groups (`(?>...)`)
- Possessive quantifiers (`*+`, `++`, `?+`)

VCL patterns using these features will pass validation in the WASM build but may fail in production or when using the native CLI.

## Usage

```html
<script src="wasm_exec.js"></script>
<script>
  const go = new Go();
  WebAssembly.instantiateStreaming(fetch("falco.wasm"), go.importObject)
    .then(result => {
      go.run(result.instance);
      // FalcoVCL is now available globally
      const result = FalcoVCL.format('sub test { set x = 1; }');
      console.log(result.formatted);
    });
</script>
```

## Build

```bash
make wasm
```

## Test

```bash
cd wasm && npm test
```

## Demo Page

Serve the directory and open `index.html` in a browser:

```bash
cd wasm && npx serve
```
