package resolver

import (
	"maps"
	"path"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/v2/ast"
)

// MapResolver resolves a main VCL and its include modules from an in-memory map
// of module-name -> source, with no filesystem access.
//
// It is used by the WASI Component Model build (cmd/falco-component), where the
// host supplies include contents up front. The component discovers the include
// graph itself (the linter calls Resolve for every include it parses), so the
// host need only provide every reachable module's source, keyed by the name
// used in include statements. It generalizes StaticResolver to support includes.
type MapResolver struct {
	mainName     string
	mainData     string
	modules      map[string]string
	includePaths []string
}

// NewMapResolver builds a MapResolver. modules maps the name used in `include`
// statements (with or without a ".vcl" suffix, optionally under one of
// includePaths) to that module's source. The map is copied to isolate it from
// later caller mutation.
func NewMapResolver(mainName, mainData string, modules map[string]string, includePaths []string) *MapResolver {
	m := make(map[string]string, len(modules))
	maps.Copy(m, modules)
	return &MapResolver{
		mainName:     mainName,
		mainData:     mainData,
		modules:      m,
		includePaths: includePaths,
	}
}

func (m *MapResolver) MainVCL() (*VCL, error) {
	return &VCL{Name: m.mainName, Data: m.mainData}, nil
}

func (m *MapResolver) Name() string           { return m.mainName }
func (m *MapResolver) IncludePaths() []string { return m.includePaths }

// Resolve looks up an include's contents in the module map. The returned
// VCL.Name is the matched map key, so diagnostics carry the real module name.
// An empty module value is rejected, and a candidate equal to mainName is
// skipped so a host module cannot shadow the synthetic main file.
func (m *MapResolver) Resolve(stmt *ast.IncludeStatement) (*VCL, error) {
	if stmt.Module.Value == "" {
		return nil, errors.New("Failed to resolve include module: empty module name")
	}
	for _, key := range m.candidates(stmt.Module.Value) {
		if key == m.mainName {
			continue
		}
		if data, ok := m.modules[key]; ok {
			return &VCL{Name: key, Data: data}, nil
		}
	}
	return nil, errors.Errorf("Failed to resolve include module: %s", stmt.Module.Value)
}

// candidates enumerates the map keys to try, in priority order: the
// ".vcl"-suffixed form first, then the value as written, each also joined under
// every include path. Duplicates are removed while preserving order.
//
// Keys are matched as forward-slash path strings, so path.Join collapses ".."
// segments into the flat key namespace. This is not a traversal risk (lookups
// only hit the in-memory map), but hosts must key the map with the same
// forward-slash names they use in `include` statements.
func (m *MapResolver) candidates(module string) []string {
	withExt := module
	if !strings.HasSuffix(withExt, ".vcl") {
		withExt += ".vcl"
	}
	bases := []string{withExt}
	if module != withExt {
		bases = append(bases, module)
	}

	seen := map[string]struct{}{}
	var out []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	for _, base := range bases {
		add(base)
		for _, p := range m.includePaths {
			add(path.Join(p, base))
		}
	}
	return out
}
