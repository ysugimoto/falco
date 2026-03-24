// Load wasm_exec.js (Go's Wasm runtime)
const wasmExecResponse = await fetch('/wasm_exec.js');
const wasmExecCode = await wasmExecResponse.text();
new Function(wasmExecCode)();

// Load and instantiate the Wasm module
const go = new globalThis.Go();
const wasmResponse = await fetch('/falco.wasm');
const wasmBuffer = await wasmResponse.arrayBuffer();
const { instance } = await WebAssembly.instantiate(wasmBuffer, go.importObject);

// Run the Go program (sets up FalcoVCL on globalThis)
go.run(instance);

// Export for tests
export { go };
