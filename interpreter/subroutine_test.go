package interpreter

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestFunctionSubroutine(t *testing.T) {

	// ref: https://github.com/ysugimoto/falco/issues/241
	t.Run("Functional subroutine returns a value", func(t *testing.T) {
		input := `
sub compute INTEGER {
  if (true) {
    return 2;
  }
  return 3;
}

sub vcl_recv {
  declare local var.myint INTEGER;
  set var.myint = compute();
  set req.http.X-Int-Value = var.myint;
}
`
		assertInterpreter(t, input, context.RecvScope, map[string]value.Value{
			"req.http.X-Int-Value": &value.String{Value: "2"},
		}, false)

	})
}
