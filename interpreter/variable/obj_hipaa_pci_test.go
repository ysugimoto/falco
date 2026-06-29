package variable

import (
	"testing"

	"github.com/ysugimoto/falco/v2/interpreter/cache"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// getter mirrors the Get signature shared across scope variable types.
type objScopeGetter interface {
	Get(context.Scope, string) (value.Value, error)
}

func TestObjHipaaPciReflectCachedObject(t *testing.T) {
	scopes := []struct {
		name  string
		scope context.Scope
		newFn func(*context.Context) objScopeGetter
	}{
		{"hit", context.HitScope, func(c *context.Context) objScopeGetter { return NewHitScopeVariables(c) }},
		{"deliver", context.DeliverScope, func(c *context.Context) objScopeGetter { return NewDeliverScopeVariables(c) }},
		{"error", context.ErrorScope, func(c *context.Context) objScopeGetter { return NewErrorScopeVariables(c) }},
		{"log", context.LogScope, func(c *context.Context) objScopeGetter { return NewLogScopeVariables(c) }},
	}

	cases := []struct {
		name    string
		hitItem *cache.CacheItem
		expectH bool
		expectP bool
	}{
		{
			name:    "cache hit with both flags",
			hitItem: &cache.CacheItem{IsHIPAA: true, IsPCI: true},
			expectH: true,
			expectP: true,
		},
		{
			name:    "cache hit with only hipaa",
			hitItem: &cache.CacheItem{IsHIPAA: true, IsPCI: false},
			expectH: true,
			expectP: false,
		},
		{
			name:    "no cache hit item falls back to false",
			hitItem: nil,
			expectH: false,
			expectP: false,
		},
	}

	for _, sc := range scopes {
		for _, tt := range cases {
			t.Run(sc.name+"/"+tt.name, func(t *testing.T) {
				ctx := context.New()
				ctx.CacheHitItem = tt.hitItem
				vars := sc.newFn(ctx)

				h, err := vars.Get(sc.scope, OBJ_IS_HIPAA)
				if err != nil {
					t.Fatalf("obj.is_hipaa unexpected error: %s", err)
				}
				if got := h.(*value.Boolean).Value; got != tt.expectH {
					t.Errorf("obj.is_hipaa = %t, want %t", got, tt.expectH)
				}

				p, err := vars.Get(sc.scope, OBJ_IS_PCI)
				if err != nil {
					t.Fatalf("obj.is_pci unexpected error: %s", err)
				}
				if got := p.(*value.Boolean).Value; got != tt.expectP {
					t.Errorf("obj.is_pci = %t, want %t", got, tt.expectP)
				}
			})
		}
	}
}
