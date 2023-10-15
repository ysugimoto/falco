package function

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func Test_override_host(t *testing.T) {

	t.Run("Override Host", func(t *testing.T) {
		tests := []struct {
			override value.Value
		}{
			{override: &value.String{Value: "example.com"}},
		}

		for _, tt := range tests {
			c := &context.Context{}
			_, err := Testing_override_host(c, tt.override)
			if err != nil {
				t.Errorf("Expected error but nil")
			}
			if c.OriginalHost != "example.com" {
				t.Errorf("OriginalHost value unmatched, expect=example.com, got=%s", c.OriginalHost)
			}
		}
	})
}
