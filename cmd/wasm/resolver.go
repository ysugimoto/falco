//go:build js && wasm

package main

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/resolver"
)

// mapResolver is an in-memory resolver backed by a caller-supplied file map.
//
// It mirrors resolver.TerraformResolver: include modules are matched by their
// module path (as written in the include statement), normalized with a ".vcl"
// suffix. Wasm has no filesystem access, so JS callers pre-read files from disk
// and pass them in via the lint `includes` option.
//
// The wasm lint path parses the main source itself and passes the AST straight
// to the linter, so only Resolve() is exercised; MainVCL() is never called and
// is therefore unsupported.
type mapResolver struct {
	modules map[string]*resolver.VCL
}

// newMapResolver builds a resolver from an include map. Include keys are
// normalized with a ".vcl" suffix so callers may pass either "shared/util" or
// "shared/util.vcl".
func newMapResolver(includes map[string]string) *mapResolver {
	modules := make(map[string]*resolver.VCL, len(includes))
	for name, data := range includes {
		key := normalizeVCLName(name)
		modules[key] = &resolver.VCL{Name: key, Data: data}
	}
	return &mapResolver{modules: modules}
}

func normalizeVCLName(name string) string {
	if !strings.HasSuffix(name, ".vcl") {
		return name + ".vcl"
	}
	return name
}

// MainVCL is unsupported: the wasm lint path supplies the main AST directly.
func (m *mapResolver) MainVCL() (*resolver.VCL, error) {
	return nil, errors.New("mapResolver does not provide MainVCL")
}

func (m *mapResolver) Resolve(stmt *ast.IncludeStatement) (*resolver.VCL, error) {
	module := normalizeVCLName(stmt.Module.Value)
	if vcl, ok := m.modules[module]; ok {
		return vcl, nil
	}
	// Message intentionally matches resolver.TerraformResolver verbatim (and the
	// wasm test asserts on it), so we keep the capitalized form despite ST1005.
	return nil, errors.Errorf("Failed to resolve include module: %s", module)
}

func (m *mapResolver) Name() string           { return "" }
func (m *mapResolver) IncludePaths() []string { return []string{} }
