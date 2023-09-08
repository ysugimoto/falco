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

func Test_fixed_time(t *testing.T) {

	fixed := time.Now().Add(-time.Hour).UTC()

	tests := []struct {
		fixed   string
		expect  time.Time
		isError bool
	}{
		{fixed: fixed.Format("2006-01-02 15:04:05"), expect: fixed},
		{fixed: "20023-01-02 15:04:05", isError: true},
	}

	for _, tt := range tests {
		c := &context.Context{}
		_, err := Testing_fixed_time(c, &value.String{Value: tt.fixed})
		if tt.isError {
			if err == nil {
				t.Errorf("Expected error but nil")
				return
			}
			continue
		}
		if err != nil {
			t.Errorf("Unexpected error on Testing_fixed_time, %s", err)
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
			t.Errorf("now: fixed time value is different, diff=%d", diff)
		}
		sec, err := v.Get(context.RecvScope, "now.sec")
		if err != nil {
			t.Errorf("Unexpected error on getting now variable, %s", err)
			return
		}
		secVal := value.Unwrap[*value.String](sec).Value
		if diff := cmp.Diff(fmt.Sprint(tt.expect.Unix()), secVal); diff != "" {
			t.Errorf("now.sec: fixed time value is different, diff=%s", diff)
		}
	}
}
