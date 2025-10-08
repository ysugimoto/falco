package function

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_Testing_fixed_access_rate(t *testing.T) {
	t.Run("Fixed by INTEGER", func(t *testing.T) {
		tests := []struct {
			rate   int64
			expect float64
		}{
			{rate: 10, expect: 10},
		}

		for _, tt := range tests {
			c := &context.Context{}
			_, err := Testing_fixed_access_rate(c, &value.Integer{Value: tt.rate})
			if err != nil {
				t.Errorf("Unexpected error on Testing_fixed_access_rate, %s", err)
				return
			}
			if c.FixedAccessRate == nil {
				t.Errorf("FixedAccessRate must be set")
				return
			}
			if *c.FixedAccessRate != tt.expect {
				t.Errorf("FixedAccessRate value is different, expect=%f, got=%f", tt.expect, *c.FixedAccessRate)
			}
		}
	})

	t.Run("Fixed by FLOAT", func(t *testing.T) {
		tests := []struct {
			rate   float64
			expect float64
		}{
			{rate: 0.5, expect: 0.5},
		}

		for _, tt := range tests {
			c := &context.Context{}
			_, err := Testing_fixed_access_rate(c, &value.Float{Value: tt.rate})
			if err != nil {
				t.Errorf("Unexpected error on Testing_fixed_access_rate, %s", err)
				return
			}
			if c.FixedAccessRate == nil {
				t.Errorf("FixedAccessRate must be set")
				return
			}
			if *c.FixedAccessRate != tt.expect {
				t.Errorf("FixedAccessRate value is different, expect=%f, got=%f", tt.expect, *c.FixedAccessRate)
			}
		}
	})

	t.Run("Argument type error", func(t *testing.T) {
		tests := []value.Value{
			&value.String{Value: "foo"},
			&value.Boolean{Value: false},
			&value.Backend{},
			&value.Acl{},
		}

		for _, tt := range tests {
			c := &context.Context{}
			_, err := Testing_fixed_access_rate(c, tt)
			if err == nil {
				t.Errorf("Expected error but got nil")
			}
		}
	})

	t.Run("Argument count error", func(t *testing.T) {
		c := &context.Context{}
		_, err := Testing_fixed_access_rate(c)
		if err == nil {
			t.Errorf("Expected error but got nil")
		}
	})
}
