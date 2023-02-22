// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Querystring_set_Name = "querystring.set"

var Querystring_set_ArgumentTypes = []value.Type{value.StringType, value.StringType, value.StringType}

func Querystring_set_Validate(args []value.Value) error {
	if len(args) != 3 {
		return errors.ArgumentNotEnough(Querystring_set_Name, 3, args)
	}
	for i := range args {
		if args[i].Type() != Querystring_set_ArgumentTypes[i] {
			return errors.TypeMismatch(Querystring_set_Name, i+1, Querystring_set_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of querystring.set
// Arguments may be:
// - STRING, STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/query-string/querystring-set/
func Querystring_set(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Querystring_set_Validate(args); err != nil {
		return value.Null, err
	}

	// Need to be implemented
	return value.Null, errors.NotImplemented("querystring.set")
}