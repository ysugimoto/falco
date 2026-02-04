//go:build js && wasm

// Package main provides the Wasm entry point for Falco VCL tools.
package main

import "syscall/js"

func main() {
	falco := js.Global().Get("Object").New()
	falco.Set("parse", js.FuncOf(parse))
	falco.Set("tokenize", js.FuncOf(tokenize))
	falco.Set("format", js.FuncOf(format))
	falco.Set("lint", js.FuncOf(lint))
	js.Global().Set("FalcoVCL", falco)

	// Keep the Go program alive
	select {}
}
