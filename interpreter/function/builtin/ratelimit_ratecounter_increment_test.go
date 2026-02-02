package builtin

import (
	"net"
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Ratelimit_ratecounter_increment(t *testing.T) {
	rc := value.NewRatecounter(nil)
	rc.Increment("127.0.0.1", 1, 0)

	tests := []struct {
		name         string
		args         []value.Value
		ratecounters map[string]*value.Ratecounter
		want         value.Value
		isErr        bool
	}{
		{
			name: "ratecounter not found",
			args: []value.Value{
				&value.Ident{Value: "example"},
				&value.String{Value: "127.0.0.1"},
				&value.Integer{Value: 1},
			},
			ratecounters: map[string]*value.Ratecounter{},
			isErr:        true,
		},
		{
			name: "increment",
			args: []value.Value{
				&value.Ident{Value: "example"},
				&value.String{Value: "127.0.0.1"},
				&value.Integer{Value: 1},
			},
			ratecounters: map[string]*value.Ratecounter{
				"example": value.NewRatecounter(nil),
			},
			want: &value.Integer{Value: 1},
		},
		{
			name: "increment with initial value",
			args: []value.Value{
				&value.Ident{Value: "example"},
				&value.String{Value: "127.0.0.1"},
				&value.Integer{Value: 1},
			},
			ratecounters: map[string]*value.Ratecounter{
				"example": rc,
			},
			want: &value.Integer{Value: 2},
		},
		{
			name: "increment with IP value",
			args: []value.Value{
				&value.Ident{Value: "example"},
				&value.IP{Value: net.ParseIP("127.0.0.1")},
				&value.Integer{Value: 1},
			},
			ratecounters: map[string]*value.Ratecounter{
				"example": value.NewRatecounter(nil),
			},
			want: &value.Integer{Value: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &context.Context{
				Ratecounters: tt.ratecounters,
			}

			val, err := Ratelimit_ratecounter_increment(ctx, tt.args...)
			if tt.isErr {
				if err == nil {
					t.Errorf("Ratelimit_ratecounter_increment() error = %v, isErr %v", err, tt.isErr)
				}
				return
			}
			if err != nil {
				t.Errorf("Ratelimit_ratecounter_increment() error = %v", err)
				return
			}
			if val.Type() != tt.want.Type() {
				t.Errorf("Unexpected type returned, want=%s, got=%s", tt.want.Type(), val.Type())
			}
			v := value.Unwrap[*value.Integer](val)
			w := value.Unwrap[*value.Integer](tt.want)
			if v.Value != w.Value {
				t.Errorf("Unexpected value returned, want=%d, got=%d", w.Value, v.Value)
			}
		})
	}
}

func Test_Ratelimit_ratecounter_increment_with_fixed_rate(t *testing.T) {
	fixedRate := 10.5

	tests := []struct {
		name         string
		args         []value.Value
		ratecounters map[string]*value.Ratecounter
		fixedRate    *float64
		want         value.Value
		isErr        bool
	}{
		{
			name: "with fixed access rate",
			args: []value.Value{
				&value.Ident{Value: "example"},
				&value.String{Value: "127.0.0.1"},
				&value.Integer{Value: 1},
			},
			ratecounters: map[string]*value.Ratecounter{
				"example": value.NewRatecounter(nil),
			},
			fixedRate: &fixedRate,
			want:      &value.Integer{Value: 630}, // 10.5 * 60 = 630
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &context.Context{
				Ratecounters:    tt.ratecounters,
				FixedAccessRate: tt.fixedRate,
			}

			val, err := Ratelimit_ratecounter_increment(ctx, tt.args...)
			if tt.isErr {
				if err == nil {
					t.Errorf("Ratelimit_ratecounter_increment() error = %v, isErr %v", err, tt.isErr)
				}
				return
			}
			if err != nil {
				t.Errorf("Ratelimit_ratecounter_increment() error = %v", err)
				return
			}
			if val.Type() != tt.want.Type() {
				t.Errorf("Unexpected type returned, want=%s, got=%s", tt.want.Type(), val.Type())
			}
			v := value.Unwrap[*value.Integer](val)
			w := value.Unwrap[*value.Integer](tt.want)
			if v.Value != w.Value {
				t.Errorf("Unexpected value returned, want=%d, got=%d", w.Value, v.Value)
			}
		})
	}
}

func Test_Ratelimit_ratecounter_increment_Validation(t *testing.T) {
	tests := []struct {
		name    string
		args    []value.Value
		isError bool
	}{
		{
			name: "not enough arguments",
			args: []value.Value{
				&value.Ident{Value: "my_rc"},
				&value.String{Value: "entry"},
			},
			isError: true,
		},
		{
			name: "too many arguments",
			args: []value.Value{
				&value.Ident{Value: "my_rc"},
				&value.String{Value: "entry"},
				&value.Integer{Value: 10},
				&value.String{Value: "extra"},
			},
			isError: true,
		},
		{
			name: "invalid argument type for first argument",
			args: []value.Value{
				&value.String{Value: "my_rc"},
				&value.String{Value: "entry"},
				&value.Integer{Value: 10},
			},
			isError: true,
		},
		{
			name: "invalid argument type for second argument",
			args: []value.Value{
				&value.Ident{Value: "my_rc"},
				&value.Integer{Value: 123},
				&value.Integer{Value: 10},
			},
			isError: true,
		},
		{
			name: "invalid argument type for third argument",
			args: []value.Value{
				&value.Ident{Value: "my_rc"},
				&value.String{Value: "entry"},
				&value.String{Value: "10"},
			},
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Ratelimit_ratecounter_increment(&context.Context{}, tt.args...)
			if tt.isError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %s", err)
				}
			}
		})
	}
}
