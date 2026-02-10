package function

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/http"
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
			req, _ := http.NewRequest("GET", "http://localhost", nil)
			req.Header.Set("Host", "localhost")
			c := &context.Context{Request: req}
			_, err := Testing_override_host(c, tt.override)
			if err != nil {
				t.Errorf("Expected error but nil")
			}
			if c.OriginalHost != "example.com" {
				t.Errorf("OriginalHost value unmatched, expect=example.com, got=%s", c.OriginalHost)
			}
			if c.Request.Header.Get("Host") != "example.com" {
				t.Errorf("Request Host header unmatched, expect=example.com, got=%s", c.Request.Header.Get("Host"))
			}
			if !c.Request.IsAssigned("Host") {
				t.Errorf("Request Host header should be marked as assigned")
			}
		}
	})
}
