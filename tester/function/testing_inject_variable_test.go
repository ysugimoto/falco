package function

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
)

func Test_inject_variable(t *testing.T) {

	t.Run("inject tentative variable", func(t *testing.T) {
		tests := []struct {
			name      string
			tentative string
			override  string
		}{
			{
				name:      "server.region",
				tentative: "US",
				override:  "ASIA",
			},
			{
				name:      "req.protocol",
				tentative: "http",
				override:  "https",
			},
		}

		for _, tt := range tests {
			// create minimal interpreter request so variable lookups that
			// reference `ctx.Request` (eg. req.protocol) won't panic
			req, _ := http.NewRequest("GET", "http://example.local/", nil) // nolint:errcheck
			c := &context.Context{
				OverrideVariables: map[string]value.Value{},
				Request:           req,
			}
			v := variable.NewAllScopeVariables(c)
			before, err := v.Get(context.RecvScope, tt.name)
			if err != nil {
				t.Errorf("Unexpected error on getting %s variable, %s", tt.name, err)
				return
			}
			bv := value.Unwrap[*value.String](before)
			if diff := cmp.Diff(bv.Value, tt.tentative); diff != "" {
				t.Errorf("tentative value is different, diff=%s", diff)
			}

			_, err = Testing_inject_variable(c, &value.String{Value: tt.name}, &value.String{Value: tt.override})
			if err != nil {
				t.Errorf("Unexpected error on Test_inject_variable, %s", err)
				return
			}

			after, err := v.Get(context.RecvScope, tt.name)
			if err != nil {
				t.Errorf("Unexpected error on getting %s variable, %s", tt.name, err)
				return
			}
			av := value.Unwrap[*value.String](after)
			if diff := cmp.Diff(av.Value, tt.override); diff != "" {
				t.Errorf("Overridden value is different, diff=%s", diff)
			}
		}
	})
}
