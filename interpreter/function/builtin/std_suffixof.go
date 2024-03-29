// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Std_suffixof_Name = "std.suffixof"

var Std_suffixof_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Std_suffixof_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Std_suffixof_Name, 2, args)
	}
	for i := range args {
		if args[i].Type() != Std_suffixof_ArgumentTypes[i] {
			return errors.TypeMismatch(Std_suffixof_Name, i+1, Std_suffixof_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of std.suffixof
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/std-suffixof/
func Std_suffixof(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Std_suffixof_Validate(args); err != nil {
		return value.Null, err
	}

	s := value.Unwrap[*value.String](args[0]).Value
	suffix := value.Unwrap[*value.String](args[1]).Value

	return &value.Boolean{Value: strings.HasSuffix(s, suffix)}, nil
}
