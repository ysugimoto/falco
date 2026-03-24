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
