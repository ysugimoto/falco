// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const H2_push_Name = "h2.push"

func H2_push_Validate(args []value.Value) error {
	if len(args) < 1 {
		return errors.ArgumentNotEnough(H2_push_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != value.StringType {
			return errors.TypeMismatch(H2_push_Name, i+1, value.StringType, args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of h2.push
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/tls-and-http/h2-push/
func H2_push(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := H2_push_Validate(args); err != nil {
		return value.Null, err
	}

	resource := value.Unwrap[*value.String](args[0])
	// Fastly document does not say about "as" variadic argument, so we ignore them for now.
	ctx.PushResources = append(ctx.PushResources, resource.Value)

	return nil, nil
}
