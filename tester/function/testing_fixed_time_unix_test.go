package function

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
)

func Test_fixed_time_unix(t *testing.T) {

	fixed := time.Now().Add(-time.Hour).UTC()

	t.Run("Fixed by INTEGER", func(t *testing.T) {
		tests := []struct {
			fixed  int64
			expect time.Time
		}{
			{fixed: fixed.Unix(), expect: fixed},
		}

		for _, tt := range tests {
			c := &context.Context{}
			_, err := Testing_fixed_time_unix(c, &value.Integer{Value: tt.fixed})
			if err != nil {
				t.Errorf("Unexpected error on Testing_fixed_time_unix, %s", err)
				return
			}
			v := variable.NewAllScopeVariables(c)
			now, err := v.Get(context.RecvScope, "now")
			if err != nil {
				t.Errorf("Unexpected error on getting now variable, %s", err)
				return
			}
			nowVal := value.Unwrap[*value.Time](now).Value
			diff := nowVal.Sub(tt.expect).Microseconds()
			if diff > 0 {
				t.Errorf("fixed time value is different, diff=%d", diff)
			}
			sec, err := v.Get(context.RecvScope, "now.sec")
			if err != nil {
				t.Errorf("Unexpected error on getting now variable, %s", err)
				return
			}
			secVal := value.Unwrap[*value.String](sec).Value
			if diff := cmp.Diff(fmt.Sprint(tt.expect.Unix()), secVal); diff != "" {
				t.Errorf("fixed time value is different, diff=%s", diff)
			}
		}
	})
	t.Run("Fixed by TIME", func(t *testing.T) {
		tests := []struct {
			fixed  time.Time
			expect time.Time
		}{
			{fixed: fixed, expect: fixed},
		}

		for _, tt := range tests {
			c := &context.Context{}
			_, err := Testing_fixed_time_unix(c, &value.Time{Value: tt.fixed})
			if err != nil {
				t.Errorf("Unexpected error on Testing_fixed_time_unix, %s", err)
				return
			}
			v := variable.NewAllScopeVariables(c)
			actual, err := v.Get(context.RecvScope, "now")
			if err != nil {
				t.Errorf("Unexpected error on getting now variable, %s", err)
				return
			}
			if diff := cmp.Diff(&value.Time{Value: tt.expect}, actual); diff != "" {
				t.Errorf("fixed time value is different, diff=%s", diff)
			}
		}
	})
	t.Run("Fixed by Other", func(t *testing.T) {
		tests := []struct {
			fixed value.Value
		}{
			{fixed: &value.Float{Value: 0}},
			{fixed: &value.String{Value: "foo"}},
			{fixed: &value.String{Value: "2023-09-08 12:00:00"}},
			{fixed: &value.Boolean{Value: false}},
			{fixed: &value.IP{Value: nil}},
			{fixed: &value.Backend{Value: nil}},
			{fixed: &value.Acl{Value: nil}},
		}

		for _, tt := range tests {
			c := &context.Context{}
			_, err := Testing_fixed_time_unix(c, tt.fixed)
			if err == nil {
				t.Errorf("Expected error but nil")
			}
		}
	})
}
