// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Std_replace_prefix_Name = "std.replace_prefix"

var Std_replace_prefix_ArgumentTypes = []value.Type{value.StringType, value.StringType, value.StringType}

func Std_replace_prefix_Validate(args []value.Value) error {
	if len(args) != 3 {
		return errors.ArgumentNotEnough(Std_replace_prefix_Name, 3, args)
	}
	for i := range args {
		if args[i].Type() != Std_replace_prefix_ArgumentTypes[i] {
			return errors.TypeMismatch(Std_replace_prefix_Name, i+1, Std_replace_prefix_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of std.replace_prefix
// Arguments may be:
// - STRING, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/std-replace-prefix/
func Std_replace_prefix(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Std_replace_prefix_Validate(args); err != nil {
		return value.Null, err
	}

	// Need to be implemented
	return value.Null, errors.NotImplemented("std.replace_prefix")
}