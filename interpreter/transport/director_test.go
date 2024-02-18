package transport

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func setupDirector(director string) (*context.Context, *flchttp.Director, error) {
	ctx, err := setup()
	if err != nil {
		return nil, nil, err
	}
	vcl, err := parser.New(lexer.NewFromString(director)).ParseVCL()
	if err != nil {
		return nil, nil, err
	}

	d, err := GetDirector(ctx, vcl.Statements[0].(*ast.DirectorDeclaration))
	if err != nil {
		return nil, nil, err
	}
	return ctx, d, nil
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
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}
		// set unhealthy
		ctx.Backends["test01"].Healthy.Store(false)
		ctx.Backends["test02"].Healthy.Store(false)

		_, err = d.Random()
		if err != flchttp.ErrQuorumWeightNotReached {
			t.Errorf("Random director should return quorum error: %s", err)
		}
	})

	t.Run("Fair randomness", func(t *testing.T) {
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}
		results := map[*value.Backend]int{}

		for i := 0; i < 10000; i++ {
			r, err := d.Random()
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
		b01 := results[ctx.Backends["test01"]] / 100
		b02 := results[ctx.Backends["test02"]] / 100
		b03 := results[ctx.Backends["test03"]] / 100
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
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}
		results := map[*value.Backend]int{}

		ctx.Backends["test03"].Healthy.Store(false)

		for i := 0; i < 10000; i++ {
			r, err := d.Random()
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
		b01 := results[ctx.Backends["test01"]] / 100
		b02 := results[ctx.Backends["test02"]] / 100
		if b01 < 65 || b01 > 68 {
			t.Errorf("test01 backend determined around 66%% probability, got %d%%", b01)
		}
		if b02 < 31 || b02 > 34 {
			t.Errorf("test02 backend determined around 33%% probability, got %d%%", b02)
		}
		// unhealthy backend should not be determined
		if _, ok := results[ctx.Backends["test03"]]; ok {
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
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}
		ctx.Backends["test01"].Healthy.Store(false)

		b, err := d.Fallback()
		if err != nil {
			t.Errorf("Fallback director backend determination failed: %s", err)
		}
		if b.Value.Name.Value != "test02" {
			t.Errorf("Fallback director should fallback to test02, but determined %s", b.Value.Name.Value)
		}
	})

	t.Run("Return all backend failed error", func(t *testing.T) {
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}

		ctx.Backends["test01"].Healthy.Store(false)
		ctx.Backends["test02"].Healthy.Store(false)
		ctx.Backends["test03"].Healthy.Store(false)

		_, err = d.Fallback()
		if err != flchttp.ErrAllBackendsFailed {
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
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}

		// set unhealthy
		ctx.Backends["test01"].Healthy.Store(false)
		ctx.Backends["test02"].Healthy.Store(false)

		ident := flchttp.DirectorIdentity{
			RequestHash:    ctx.RequestHash.Value,
			ClientIdentity: ctx.ClientIdentity.Value,
		}

		_, err = d.Hash(ident)
		if err != flchttp.ErrQuorumWeightNotReached {
			t.Errorf("Content director should return quorum error: %s", err)
		}
	})

	t.Run("Determined same backend", func(t *testing.T) {
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}
		results := map[*value.Backend]int{}

		ident := flchttp.DirectorIdentity{
			RequestHash:    ctx.RequestHash.Value,
			ClientIdentity: ctx.ClientIdentity.Value,
		}

		for i := 0; i < 10000; i++ {
			r, err := d.Hash(ident)
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
		b01 := results[ctx.Backends["test01"]] / 100
		b02 := results[ctx.Backends["test02"]] / 100
		b03 := results[ctx.Backends["test03"]] / 100
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
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}

		// set unhealthy
		ctx.Backends["test01"].Healthy.Store(false)
		ctx.Backends["test02"].Healthy.Store(false)

		ident := flchttp.DirectorIdentity{
			RequestHash:    ctx.RequestHash.Value,
			ClientIdentity: ctx.ClientIdentity.Value,
		}
		_, err = d.Client(ident)
		if err != flchttp.ErrQuorumWeightNotReached {
			t.Errorf("Client director should return quorum error: %s", err)
		}
	})

	t.Run("Determined same backend", func(t *testing.T) {
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}
		results := map[*value.Backend]int{}

		ident := flchttp.DirectorIdentity{
			RequestHash:    ctx.RequestHash.Value,
			ClientIdentity: ctx.ClientIdentity.Value,
		}

		for i := 0; i < 10000; i++ {
			r, err := d.Client(ident)
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
		b01 := results[ctx.Backends["test01"]] / 100
		b02 := results[ctx.Backends["test02"]] / 100
		b03 := results[ctx.Backends["test03"]] / 100
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
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}

		// set unhealthy
		ctx.Backends["test01"].Healthy.Store(false)
		ctx.Backends["test02"].Healthy.Store(false)

		ident := flchttp.DirectorIdentity{
			RequestHash:    ctx.RequestHash.Value,
			ClientIdentity: ctx.ClientIdentity.Value,
		}

		_, err = d.ConsistentHash(ident)
		if err != flchttp.ErrQuorumWeightNotReached {
			t.Errorf("Chash director should return quorum error: %s", err)
		}
	})

	t.Run("Determined same backend for object key", func(t *testing.T) {
		ctx, d, err := setupDirector(director)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}
		results := map[*value.Backend]int{}

		ident := flchttp.DirectorIdentity{
			RequestHash:    ctx.RequestHash.Value,
			ClientIdentity: ctx.ClientIdentity.Value,
		}

		for i := 0; i < 10000; i++ {
			r, err := d.ConsistentHash(ident)
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
		b01 := results[ctx.Backends["test01"]] / 100
		b02 := results[ctx.Backends["test02"]] / 100
		b03 := results[ctx.Backends["test03"]] / 100
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
		ctx, d, err := setupDirector(director2)
		if err != nil {
			t.Errorf("Failed to setup director: %s", err)
		}
		results := map[*value.Backend]int{}

		ident := flchttp.DirectorIdentity{
			RequestHash:    ctx.RequestHash.Value,
			ClientIdentity: ctx.ClientIdentity.Value,
		}

		for i := 0; i < 10000; i++ {
			r, err := d.ConsistentHash(ident)
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
		b01 := results[ctx.Backends["test01"]] / 100
		b02 := results[ctx.Backends["test02"]] / 100
		b03 := results[ctx.Backends["test03"]] / 100
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
