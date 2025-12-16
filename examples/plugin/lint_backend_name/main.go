package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/plugin"
)

func main() {
	// Read from stdin and decode AST tree struct from main falco linter.
	// Note that this function needs generics, it specified type conversion of provided statement.
	// In this case, linting for *ast.BackendDeclaration object.
	req, err := plugin.ReadLinterRequest[*ast.BackendDeclaration](os.Stdin)
	if err != nil {
		// If some error has occurred, send back message to stderr
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// Prepare send back response message
	resp := &plugin.LinterResponse{}

	// Main linting logic, the backend name must have "F_" prefix
	// By using generics, req.Statement could be *ast.BackendDeclaration pointer.
	if !strings.HasPrefix(req.Statement.Name.Value, "F_") {
		resp.Error(`Backend name must start with "F_"`)
	}

	// Send back result message to stdout including some linting errors
	if err := resp.Write(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
