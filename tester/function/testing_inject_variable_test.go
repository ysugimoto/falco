package function

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	ihttp "github.com/ysugimoto/falco/interpreter/http"
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
		}

		for _, tt := range tests {
			c := &context.Context{
				OverrideVariables: map[string]value.Value{},
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

	t.Run("inject req.body variable", func(t *testing.T) {
		c := &context.Context{
			Request:           ihttp.WrapRequest(&http.Request{Method: http.MethodPost}),
			OverrideVariables: map[string]value.Value{},
		}
		v := variable.NewAllScopeVariables(c)

		// Before injection, req.body should return empty string (nil body)
		before, err := v.Get(context.RecvScope, "req.body")
		if err != nil {
			t.Errorf("Unexpected error on getting req.body, %s", err)
			return
		}
		bv := value.Unwrap[*value.String](before)
		if diff := cmp.Diff(bv.Value, ""); diff != "" {
			t.Errorf("default value is different, diff=%s", diff)
		}

		// Inject override
		_, err = Testing_inject_variable(c, &value.String{Value: "req.body"}, &value.String{Value: "bodytext"})
		if err != nil {
			t.Errorf("Unexpected error on Testing_inject_variable, %s", err)
			return
		}

		// After injection, req.body should return overridden value
		after, err := v.Get(context.RecvScope, "req.body")
		if err != nil {
			t.Errorf("Unexpected error on getting req.body, %s", err)
			return
		}
		av := value.Unwrap[*value.String](after)
		if diff := cmp.Diff(av.Value, "bodytext"); diff != "" {
			t.Errorf("Overridden value is different, diff=%s", diff)
		}
	})

	t.Run("inject req.body.base64 variable", func(t *testing.T) {
		c := &context.Context{
			Request:           ihttp.WrapRequest(&http.Request{Method: http.MethodPost}),
			OverrideVariables: map[string]value.Value{},
		}
		v := variable.NewAllScopeVariables(c)

		// Inject override
		_, err := Testing_inject_variable(c, &value.String{Value: "req.body.base64"}, &value.String{Value: "Ym9keXRleHQ="})
		if err != nil {
			t.Errorf("Unexpected error on Testing_inject_variable, %s", err)
			return
		}

		// After injection, req.body.base64 should return overridden value
		after, err := v.Get(context.RecvScope, "req.body.base64")
		if err != nil {
			t.Errorf("Unexpected error on getting req.body.base64, %s", err)
			return
		}
		av := value.Unwrap[*value.String](after)
		if diff := cmp.Diff(av.Value, "Ym9keXRleHQ="); diff != "" {
			t.Errorf("Overridden value is different, diff=%s", diff)
		}
	})

	t.Run("inject req.body works for GET request", func(t *testing.T) {
		c := &context.Context{
			Request:           ihttp.WrapRequest(&http.Request{Method: http.MethodGet}),
			OverrideVariables: map[string]value.Value{},
		}
		v := variable.NewAllScopeVariables(c)

		// Without injection, GET request returns empty body
		before, err := v.Get(context.RecvScope, "req.body")
		if err != nil {
			t.Errorf("Unexpected error on getting req.body, %s", err)
			return
		}
		bv := value.Unwrap[*value.String](before)
		if diff := cmp.Diff(bv.Value, ""); diff != "" {
			t.Errorf("default value is different, diff=%s", diff)
		}

		// Inject override - should work even for GET request
		_, err = Testing_inject_variable(c, &value.String{Value: "req.body"}, &value.String{Value: "injected"})
		if err != nil {
			t.Errorf("Unexpected error on Testing_inject_variable, %s", err)
			return
		}

		after, err := v.Get(context.RecvScope, "req.body")
		if err != nil {
			t.Errorf("Unexpected error on getting req.body, %s", err)
			return
		}
		av := value.Unwrap[*value.String](after)
		if diff := cmp.Diff(av.Value, "injected"); diff != "" {
			t.Errorf("Overridden value is different, diff=%s", diff)
		}
	})
}
