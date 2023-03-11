// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of h2.push
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/tls-and-http/h2-push/
func Test_H2_push(t *testing.T) {
	ctx := &context.Context{}
	ret, err := H2_push(
		ctx,
		&value.String{Value: "/styles.css"},
		&value.String{Value: "as"},
	)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if ret != nil {
		t.Errorf("Return type must be nil")
	}

	// compare stacked result
	resources := ctx.PushResources
	if len(resources) != 1 {
		t.Errorf("Push resources count must be 1, got %d", len(resources))
		return
	}
	for i, v := range []string{"/styles.css"} {
		if resources[i] != v {
			t.Errorf("%d push resource must be %s, got=%s", i, v, resources[i])
		}
	}
}