package variable

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestOverrideVariables(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]any
		expect    any
	}{
		{
			name: "client.bot.name",
			overrides: map[string]any{
				"client.bot.name": "overridden",
			},
			expect: "overridden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.New(context.WithOverrideVariables(tt.overrides))
			vars := NewAllScopeVariables(ctx)
			v, err := vars.Get(context.RecvScope, tt.name)
			if err != nil {
				t.Errorf("Unexpected error: %s", err)
				return
			}
			var expect value.Value
			switch t := tt.expect.(type) {
			case int:
				expect = &value.Integer{Value: int64(t)}
			case string:
				expect = &value.String{Value: t}
			case float64:
				expect = &value.Float{Value: float64(t)}
			case bool:
				expect = &value.Boolean{Value: t}
			default:
				expect = value.Null
			}
			if diff := cmp.Diff(expect, v); diff != "" {
				t.Errorf("Overridden variable mismatch, diff=%s", diff)
			}
		})
	}
}
