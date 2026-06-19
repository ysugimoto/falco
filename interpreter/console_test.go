package interpreter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// ConsoleProcessInit synthesizes the request that drives console evaluation.
// req.body_bytes_read reads req.Body in the deliver and log scopes. net/http
// guarantees a server request's Body is always non-nil
// (https://pkg.go.dev/net/http#Request.Body), so the synthetic request must
// carry a non-nil body (http.NoBody) for the read to return 0 instead of
// dereferencing nil and panicking.
func TestConsoleRequestBodyByteReads(t *testing.T) {
	scopes := []struct {
		name  string
		scope context.Scope
	}{
		{name: "deliver", scope: context.DeliverScope},
		{name: "log", scope: context.LogScope},
	}

	for _, sc := range scopes {
		t.Run("req.body_bytes_read in "+sc.name+" scope", func(t *testing.T) {
			ip := New()
			if err := ip.ConsoleProcessInit(); err != nil {
				t.Fatalf("ConsoleProcessInit failed: %s", err)
			}
			ip.SetScope(sc.scope)

			got, err := ip.vars.Get(sc.scope, "req.body_bytes_read")
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if diff := cmp.Diff(value.Value(&value.Integer{Value: 0}), got); diff != "" {
				t.Errorf("Return value unmatch, diff=%s", diff)
			}
		})
	}
}
