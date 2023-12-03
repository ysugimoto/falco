package interpreter

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

var backends = `
backend test01 {
  .host = "example01.com";
  .port = "443";
}

backend test02 {
  .host = "example02.com";
  .port = "443";
}

backend test03 {
  .host = "example03.com";
  .port = "443";
}
`

func createTestInterpreter(director string) (*Interpreter, error) {
	vcl, err := parser.New(lexer.NewFromString(backends + director)).ParseVCL()
	if err != nil {
		return nil, fmt.Errorf("VCL parser error: %s", err)
	}
	if len(vcl.Statements) != 4 {
		return nil, fmt.Errorf("Parsed statement should be 4, got: %d", len(vcl.Statements))
	}
	_, ok := vcl.Statements[3].(*ast.DirectorDeclaration)
	if !ok {
		return nil, fmt.Errorf("Failed to get director declaration")
	}
	ip := New()
	ip.ctx = context.New()
	ip.ctx.RequestHash = &value.String{
		Value: "/?foo=bar",
	}
	ip.ctx.ClientIdentity = &value.String{
		Value: "127.0.0.1",
	}
	if err := ip.ProcessDeclarations(vcl.Statements); err != nil {
		return nil, fmt.Errorf("Failed to process statement: %s", err)
	}

	return ip, nil
}

func TestGetDirectorConfig(t *testing.T) {
	director := `
director test random {
  .quorum  = 50%;
  .retries = 3;
  { .backend = test01; .weight = 2; }
  { .backend = test02; .weight = 1; }
  { .backend = test03; .weight = 1; }
}
`
	ip, err := createTestInterpreter(director)
	if err != nil {
		t.Errorf("Failed to create interpreter: %s", err)
	}
	d := ip.ctx.Backends["test"].Director

	expect := &value.DirectorConfig{
		Quorum:  50,
		Retries: 3,
		Name:    "test",
		Type:    "random",
		Backends: []*value.DirectorConfigBackend{
			{Backend: ip.ctx.Backends["test01"], Weight: 2},
			{Backend: ip.ctx.Backends["test02"], Weight: 1},
			{Backend: ip.ctx.Backends["test03"], Weight: 1},
		},
	}
	if diff := cmp.Diff(expect, d, cmpopts.IgnoreFields(value.Backend{}, "Healthy")); diff != "" {
		t.Errorf("getDirectorConfig returns diff: %s", diff)
	}
}

func TestGetDirectorConfigShield(t *testing.T) {
	director := "director test shield { }"
	ip, err := createTestInterpreter(director)
	if err != nil {
		t.Errorf("Failed to create interpreter: %s", err)
	}
	d := ip.ctx.Backends["test"].Director

	expect := &value.DirectorConfig{
		Quorum:  0,
		Retries: 0,
		Name:    "test",
		Type:    "shield",
	}
	if diff := cmp.Diff(expect, d, cmpopts.IgnoreFields(value.Backend{}, "Healthy")); diff != "" {
		t.Errorf("getDirectorConfig returns diff: %s", diff)
	}
}

func TestRandomDirector(t *testing.T) {
	director := `
director test random {
  .quorum  = 50%;
  .retries = 3;
  { .backend = test01; .weight = 2; }
  { .backend = test02; .weight = 1; }
  { .backend = test03; .weight = 1; }
}
`
	t.Run("Expect quorum weight not reached error", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director

		// set unhealthy
		ip.ctx.Backends["test01"].Healthy.Store(false)
		ip.ctx.Backends["test02"].Healthy.Store(false)

		_, err = ip.directorBackendRandom(d)
		if err != ErrQuorumWeightNotReached {
			t.Errorf("Random director should return quorum error: %s", err)
		}
	})

	t.Run("Fair randomness", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director
		results := map[*value.Backend]int{}

		for i := 0; i < 10000; i++ {
			r, err := ip.directorBackendRandom(d)
			if err != nil {
				t.Errorf("Random director backend determination failed: %s", err)
				return
			}
			if _, ok := results[r]; !ok {
				results[r] = 0
			}
			results[r]++
		}

		// Random result possibly different for each testing, so we accept 2% differ
		b01 := results[ip.ctx.Backends["test01"]] / 100
		b02 := results[ip.ctx.Backends["test02"]] / 100
		b03 := results[ip.ctx.Backends["test03"]] / 100
		if b01 < 48 || b01 > 52 {
			t.Errorf("test01 backend determined around 50%% probability, got %d%%", b01)
		}
		if b02 < 23 || b02 > 27 {
			t.Errorf("test02 backend determined around 25%% probability, got %d%%", b02)
		}
		if b03 < 23 || b03 > 27 {
			t.Errorf("test03 backend determined around 25%% probability, got %d%%", b03)
		}
	})

	t.Run("Only healthy backends are determined", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director
		results := map[*value.Backend]int{}

		ip.ctx.Backends["test03"].Healthy.Store(false)

		for i := 0; i < 10000; i++ {
			r, err := ip.directorBackendRandom(d)
			if err != nil {
				t.Errorf("Random director backend determination failed: %s", err)
				return
			}
			if _, ok := results[r]; !ok {
				results[r] = 0
			}
			results[r]++
		}

		// Random result possibly different for each testing, so we accept 2% differ
		b01 := results[ip.ctx.Backends["test01"]] / 100
		b02 := results[ip.ctx.Backends["test02"]] / 100
		if b01 < 65 || b01 > 68 {
			t.Errorf("test01 backend determined around 66%% probability, got %d%%", b01)
		}
		if b02 < 31 || b02 > 34 {
			t.Errorf("test02 backend determined around 33%% probability, got %d%%", b02)
		}
		// unhealthy backend should not be determined
		if _, ok := results[ip.ctx.Backends["test03"]]; ok {
			t.Errorf("test03 backend is unhealthy but determined")
		}
	})
}

func TestFallbackDirectorest(t *testing.T) {
	director := `
director test fallback {
  { .backend = test01; }
  { .backend = test02; }
  { .backend = test03; }
}
`
	t.Run("Unhealthy backend should not determined", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director

		ip.ctx.Backends["test01"].Healthy.Store(false)

		b, err := ip.directorBackendFallback(d)
		if err != nil {
			t.Errorf("Fallback director backend determination failed: %s", err)
		}
		if b.Value.Name.Value != "test02" {
			t.Errorf("Fallback director should fallback to test02, but determined %s", b.Value.Name.Value)
		}
	})

	t.Run("Return all backend failed error", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director

		ip.ctx.Backends["test01"].Healthy.Store(false)
		ip.ctx.Backends["test02"].Healthy.Store(false)
		ip.ctx.Backends["test03"].Healthy.Store(false)

		_, err = ip.directorBackendFallback(d)
		if err != ErrAllBackendsFailed {
			t.Errorf("Fallback director should return all backends failed error: %s", err)
		}
	})
}

func TestContentDirector(t *testing.T) {
	director := `
director test hash {
  .quorum  = 50%;
  { .backend = test01; .weight = 1; }
  { .backend = test02; .weight = 1; } { .backend = test03; .weight = 1; }
}
`
	t.Run("Expect quorum weight not reached error", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director

		// set unhealthy
		ip.ctx.Backends["test01"].Healthy.Store(false)
		ip.ctx.Backends["test02"].Healthy.Store(false)

		_, err = ip.directorBackendHash(d)
		if err != ErrQuorumWeightNotReached {
			t.Errorf("Content director should return quorum error: %s", err)
		}
	})

	t.Run("Determined same backend", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director
		results := map[*value.Backend]int{}

		for i := 0; i < 10000; i++ {
			r, err := ip.directorBackendHash(d)
			if err != nil {
				t.Errorf("Hash director backend determination failed: %s", err)
				return
			}
			if _, ok := results[r]; !ok {
				results[r] = 0
			}
			results[r]++
		}

		// Hash result always choose same backend
		b01 := results[ip.ctx.Backends["test01"]] / 100
		b02 := results[ip.ctx.Backends["test02"]] / 100
		b03 := results[ip.ctx.Backends["test03"]] / 100
		if b01 != 0 {
			t.Errorf("test01 backend determined 0%% probability, got %d%%", b01)
		}
		if b02 != 100 {
			t.Errorf("test02 backend determined 100%% probability, got %d%%", b02)
		}
		if b03 != 0 {
			t.Errorf("test03 backend determined 0%% probability, got %d%%", b03)
		}
	})
}

func TestClientDirector(t *testing.T) {
	director := `
director test client {
  .quorum  = 50%;
  { .backend = test01; .weight = 1; }
  { .backend = test02; .weight = 1; }
  { .backend = test03; .weight = 1; }
}
`
	t.Run("Expect quorum weight not reached error", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director

		// set unhealthy
		ip.ctx.Backends["test01"].Healthy.Store(false)
		ip.ctx.Backends["test02"].Healthy.Store(false)

		_, err = ip.directorBackendClient(d)
		if err != ErrQuorumWeightNotReached {
			t.Errorf("Client director should return quorum error: %s", err)
		}
	})

	t.Run("Determined same backend", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director
		results := map[*value.Backend]int{}

		for i := 0; i < 10000; i++ {
			r, err := ip.directorBackendClient(d)
			if err != nil {
				t.Errorf("Client director backend determination failed: %s", err)
				return
			}
			if _, ok := results[r]; !ok {
				results[r] = 0
			}
			results[r]++
		}

		// Hash result always choose same backend
		b01 := results[ip.ctx.Backends["test01"]] / 100
		b02 := results[ip.ctx.Backends["test02"]] / 100
		b03 := results[ip.ctx.Backends["test03"]] / 100
		if b01 != 100 {
			t.Errorf("test01 backend determined 100%% probability, got %d%%", b01)
		}
		if b02 != 0 {
			t.Errorf("test02 backend determined 0%% probability, got %d%%", b02)
		}
		if b03 != 0 {
			t.Errorf("test03 backend determined 0%% probability, got %d%%", b03)
		}
	})
}

func TestChashDirector(t *testing.T) {
	director := `
director test chash {
  .quorum = 50%;
  .seed   = 1;
  .key    = object;
  { .backend = test01; .id = "b01"; }
  { .backend = test02; .id = "b02"; }
  { .backend = test03; .id = "b03"; }
}
`
	director2 := `
director test chash {
  .quorum = 50%;
  .seed   = 1;
  .key    = client;
  { .backend = test01; .id = "b01"; }
  { .backend = test02; .id = "b02"; }
  { .backend = test03; .id = "b03"; }
}
`
	t.Run("Expect quorum weight not reached error", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director

		// set unhealthy
		ip.ctx.Backends["test01"].Healthy.Store(false)
		ip.ctx.Backends["test02"].Healthy.Store(false)

		_, err = ip.directorBackendConsistentHash(d)
		if err != ErrQuorumWeightNotReached {
			t.Errorf("Chash director should return quorum error: %s", err)
		}
	})

	t.Run("Determined same backend for object key", func(t *testing.T) {
		ip, err := createTestInterpreter(director)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director
		results := map[*value.Backend]int{}

		for i := 0; i < 10000; i++ {
			r, err := ip.directorBackendConsistentHash(d)
			if err != nil {
				t.Errorf("Chash director backend determination failed: %s", err)
				return
			}
			if _, ok := results[r]; !ok {
				results[r] = 0
			}
			results[r]++
		}

		// Hash result always choose same backend
		b01 := results[ip.ctx.Backends["test01"]] / 100
		b02 := results[ip.ctx.Backends["test02"]] / 100
		b03 := results[ip.ctx.Backends["test03"]] / 100
		if b01 != 0 {
			t.Errorf("test01 backend determined 0%% probability, got %d%%", b01)
		}
		if b02 != 0 {
			t.Errorf("test02 backend determined 0%% probability, got %d%%", b02)
		}
		if b03 != 100 {
			t.Errorf("test03 backend determined 100%% probability, got %d%%", b03)
		}
	})

	t.Run("Determined same backend for client key", func(t *testing.T) {
		ip, err := createTestInterpreter(director2)
		if err != nil {
			t.Errorf("Failed to create interpreter: %s", err)
		}
		d := ip.ctx.Backends["test"].Director
		results := map[*value.Backend]int{}

		for i := 0; i < 10000; i++ {
			r, err := ip.directorBackendConsistentHash(d)
			if err != nil {
				t.Errorf("Chash director backend determination failed: %s", err)
				return
			}
			if _, ok := results[r]; !ok {
				results[r] = 0
			}
			results[r]++
		}

		// Hash result always choose same backend
		b01 := results[ip.ctx.Backends["test01"]] / 100
		b02 := results[ip.ctx.Backends["test02"]] / 100
		b03 := results[ip.ctx.Backends["test03"]] / 100
		if b01 != 100 {
			t.Errorf("test01 backend determined 100%% probability, got %d%%", b01)
		}
		if b02 != 0 {
			t.Errorf("test02 backend determined 0%% probability, got %d%%", b02)
		}
		if b03 != 0 {
			t.Errorf("test03 backend determined 0%% probability, got %d%%", b03)
		}
	})
}
