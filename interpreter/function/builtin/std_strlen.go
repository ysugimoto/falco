// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Std_strlen_Name = "std.strlen"

var Std_strlen_ArgumentTypes = []value.Type{value.StringType}

func Std_strlen_Validate(args []value.Value) error {
	if len(args) != 1 {
		return errors.ArgumentNotEnough(Std_strlen_Name, 1, args)
	}
	for i := range args {
		if args[i].Type() != Std_strlen_ArgumentTypes[i] {
			return errors.TypeMismatch(Std_strlen_Name, i+1, Std_strlen_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of std.strlen
// Arguments may be:
// - STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/std-strlen/
func Std_strlen(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Std_strlen_Validate(args); err != nil {
		return value.Null, err
	}

	// Need to be implemented
	return value.Null, errors.NotImplemented("std.strlen")
}