package resolver

import (
	"testing"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/token"
)

func includeStmt(module string) *ast.IncludeStatement {
	return &ast.IncludeStatement{
		Module: &ast.String{
			Meta:  &ast.Meta{Token: token.Token{Type: token.STRING, Literal: module}},
			Value: module,
		},
	}
}

func TestMapResolverMainVCL(t *testing.T) {
	r := NewMapResolver("input.vcl", "sub vcl_recv {}", nil, nil)
	main, err := r.MainVCL()
	if err != nil {
		t.Fatalf("MainVCL error: %v", err)
	}
	if main.Name != "input.vcl" || main.Data != "sub vcl_recv {}" {
		t.Fatalf("unexpected main: %+v", main)
	}
}

func TestMapResolverResolve(t *testing.T) {
	modules := map[string]string{
		"mod_a":         "// a", // keyed without extension
		"mod_b.vcl":     "// b", // keyed with extension
		"inc/mod_c.vcl": "// c", // keyed under an include path
	}
	r := NewMapResolver("input.vcl", "main", modules, []string{"inc"})

	cases := []struct {
		module   string
		wantName string
		wantData string
	}{
		{"mod_a", "mod_a", "// a"},         // extension optional, raw key
		{"mod_b", "mod_b.vcl", "// b"},     // .vcl-suffixed key preferred
		{"mod_b.vcl", "mod_b.vcl", "// b"}, // explicit extension
		{"mod_c", "inc/mod_c.vcl", "// c"}, // found under include path
	}
	for _, c := range cases {
		vcl, err := r.Resolve(includeStmt(c.module))
		if err != nil {
			t.Fatalf("Resolve(%q) error: %v", c.module, err)
		}
		if vcl.Name != c.wantName || vcl.Data != c.wantData {
			t.Fatalf("Resolve(%q) = {%q, %q}, want {%q, %q}",
				c.module, vcl.Name, vcl.Data, c.wantName, c.wantData)
		}
	}
}

func TestMapResolverResolveMissing(t *testing.T) {
	r := NewMapResolver("input.vcl", "main", map[string]string{"mod_a": "// a"}, nil)
	if _, err := r.Resolve(includeStmt("nope")); err == nil {
		t.Fatal("expected error for missing module, got nil")
	}
}

// TestMapResolverExtensionAsymmetry pins that a ".vcl"-suffixed module value is
// not stripped, so it never matches a map keyed without the extension.
func TestMapResolverExtensionAsymmetry(t *testing.T) {
	r := NewMapResolver("input.vcl", "main", map[string]string{"mod_a": "// a"}, nil)
	if _, err := r.Resolve(includeStmt("mod_a.vcl")); err == nil {
		t.Fatal("include \"mod_a.vcl\" must not match a map keyed \"mod_a\" (no suffix stripping)")
	}
}

// TestMapResolverDotDotNormalization documents that path.Join collapses ".."
// segments into the flat key namespace: include "../secret" under include path
// "inc" resolves to a top-level key "secret.vcl".
func TestMapResolverDotDotNormalization(t *testing.T) {
	r := NewMapResolver("input.vcl", "main", map[string]string{"secret.vcl": "// s"}, []string{"inc"})
	vcl, err := r.Resolve(includeStmt("../secret"))
	if err != nil {
		t.Fatalf("Resolve(\"../secret\") error: %v", err)
	}
	if vcl.Name != "secret.vcl" || vcl.Data != "// s" {
		t.Fatalf("want secret.vcl/// s, got %q/%q", vcl.Name, vcl.Data)
	}
}

// TestMapResolverEmptyModule rejects an empty include value rather than
// resolving it to a surprising key (".vcl", or an include-path name).
func TestMapResolverEmptyModule(t *testing.T) {
	r := NewMapResolver("input.vcl", "main", map[string]string{"inc": "// x"}, []string{"inc"})
	if _, err := r.Resolve(includeStmt("")); err == nil {
		t.Fatal("expected error for empty module value")
	}
}

// TestMapResolverMainNameCollision ensures a host module keyed with the
// synthetic main name cannot resolve as an include (which would shadow main).
func TestMapResolverMainNameCollision(t *testing.T) {
	r := NewMapResolver("input.vcl", "main", map[string]string{"input.vcl": "// shadow"}, nil)
	if _, err := r.Resolve(includeStmt("input.vcl")); err == nil {
		t.Fatal("a module keyed as the main name must not resolve as an include")
	}
}

func TestMapResolverCopiesModules(t *testing.T) {
	src := map[string]string{"mod_a": "// a"}
	r := NewMapResolver("input.vcl", "main", src, nil)
	// Mutating the caller's map after construction must not affect resolution.
	delete(src, "mod_a")
	src["mod_a"] = "tampered"
	vcl, err := r.Resolve(includeStmt("mod_a"))
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if vcl.Data != "// a" {
		t.Fatalf("module map not copied: got %q", vcl.Data)
	}
}

// TestMapResolverPrecedence pins the documented candidate ordering: the
// ".vcl"-suffixed key wins over the bare key, and a bare key wins over the same
// base joined under an include path.
func TestMapResolverPrecedence(t *testing.T) {
	t.Run(".vcl suffix beats bare", func(t *testing.T) {
		r := NewMapResolver("input.vcl", "main", map[string]string{
			"dup":     "// bare",
			"dup.vcl": "// ext",
		}, nil)
		vcl, err := r.Resolve(includeStmt("dup"))
		if err != nil {
			t.Fatalf("Resolve error: %v", err)
		}
		if vcl.Name != "dup.vcl" || vcl.Data != "// ext" {
			t.Fatalf("want dup.vcl/// ext, got %q/%q", vcl.Name, vcl.Data)
		}
	})

	t.Run("bare beats include-path join", func(t *testing.T) {
		r := NewMapResolver("input.vcl", "main", map[string]string{
			"mod.vcl":     "// bare",
			"inc/mod.vcl": "// under inc",
		}, []string{"inc"})
		vcl, err := r.Resolve(includeStmt("mod"))
		if err != nil {
			t.Fatalf("Resolve error: %v", err)
		}
		if vcl.Name != "mod.vcl" || vcl.Data != "// bare" {
			t.Fatalf("want bare mod.vcl, got %q/%q", vcl.Name, vcl.Data)
		}
	})
}

// TestMapResolverMultipleIncludePaths checks that include paths are tried in the
// order given (first match wins).
func TestMapResolverMultipleIncludePaths(t *testing.T) {
	r := NewMapResolver("input.vcl", "main", map[string]string{
		"a/mod.vcl": "// from a",
		"b/mod.vcl": "// from b",
	}, []string{"a", "b"})
	vcl, err := r.Resolve(includeStmt("mod"))
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if vcl.Name != "a/mod.vcl" {
		t.Fatalf("first include path should win: got %q", vcl.Name)
	}

	// With only the second path's module present, resolution falls through to it.
	r2 := NewMapResolver("input.vcl", "main", map[string]string{
		"b/mod.vcl": "// from b",
	}, []string{"a", "b"})
	vcl, err = r2.Resolve(includeStmt("mod"))
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if vcl.Name != "b/mod.vcl" {
		t.Fatalf("second include path should resolve: got %q", vcl.Name)
	}
}

// TestMapResolverGetters covers Name/IncludePaths and the empty-include-path
// edge (path.Join("", base) must dedup against the bare base, not shadow it).
func TestMapResolverGetters(t *testing.T) {
	r := NewMapResolver("input.vcl", "main", map[string]string{"mod_a": "// a"}, []string{"inc"})
	if r.Name() != "input.vcl" {
		t.Fatalf("Name() = %q, want input.vcl", r.Name())
	}
	if ip := r.IncludePaths(); len(ip) != 1 || ip[0] != "inc" {
		t.Fatalf("IncludePaths() = %v, want [inc]", ip)
	}

	// An empty include path entry must not break the bare lookup.
	r2 := NewMapResolver("input.vcl", "main", map[string]string{"mod_a": "// a"}, []string{""})
	if _, err := r2.Resolve(includeStmt("mod_a")); err != nil {
		t.Fatalf("empty include path broke bare resolution: %v", err)
	}
}
