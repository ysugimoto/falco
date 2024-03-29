// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of time.runits
// Arguments may be:
// - STRING, RTIME
// Reference: https://developer.fastly.com/reference/vcl/functions/date-and-time/time-runits/
func Test_Time_runits(t *testing.T) {
	tests := []struct {
		unit    string
		rtime   time.Duration
		expect  string
		isError bool
	}{
		{unit: "s", rtime: time.Duration(time.Second), expect: "1"},
		{unit: "ms", rtime: time.Duration(time.Second), expect: "1.000"},
		{unit: "us", rtime: time.Duration(time.Second), expect: "1.000000"},
		{unit: "ns", rtime: time.Duration(time.Second), expect: "1.000000000"},
		{unit: "z", rtime: time.Duration(time.Second), expect: "", isError: true},
	}

	for i, tt := range tests {
		ret, err := Time_runits(
			&context.Context{},
			&value.String{Value: tt.unit},
			&value.RTime{Value: tt.rtime},
		)
		if err != nil {
			if !tt.isError {
				t.Errorf("[%d] Unexpected error: %s", i, err)
			}
			continue
		}
		if ret.Type() != value.StringType {
			t.Errorf("[%d] Unexpected return type, expect=STRING, got=%s", i, ret.Type())
		}
		v := value.Unwrap[*value.String](ret)
		if diff := cmp.Diff(tt.expect, v.Value); diff != "" {
			t.Errorf("[%d] Return value unmatch, diff=%s", i, diff)
		}
	}
}
