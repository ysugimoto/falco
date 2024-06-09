package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/plugin"
)

func main() {
	req, err := plugin.ReadLinterRequest[*ast.BackendDeclaration](os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	resp := &plugin.LinterResponse{}
	if !strings.HasPrefix(req.Statement.Name.Value, "F_") {
		resp.Error(`Backend name must start with "F_"`)
	}

	resp.Write(os.Stdout)
}
