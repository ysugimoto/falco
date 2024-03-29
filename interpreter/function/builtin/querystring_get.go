// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"net/url"
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Querystring_get_Name = "querystring.get"

var Querystring_get_ArgumentTypes = []value.Type{value.StringType, value.StringType}

func Querystring_get_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Querystring_get_Name, 2, args)
	}
	for i := range args {
		if args[i].Type() != Querystring_get_ArgumentTypes[i] {
			return errors.TypeMismatch(Querystring_get_Name, i+1, Querystring_get_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of querystring.get
// Arguments may be:
// - STRING, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/query-string/querystring-get/
func Querystring_get(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Querystring_get_Validate(args); err != nil {
		return value.Null, err
	}

	v := value.Unwrap[*value.String](args[0])
	name := value.Unwrap[*value.String](args[1])

	var qs string
	if idx := strings.Index(v.Value, "?"); idx != -1 {
		qs = v.Value[idx+1:]
	}

	// url.Value could not treat not set query value:
	// ?name  => should return empty string, but returns empty string
	// ?name= => should return not set, but returns empty string
	// so we try to parse from RawQuery string, not using url.Value
	for _, query := range strings.Split(qs, "&") {
		sp := strings.Split(query, "=")
		if len(sp) < 2 || sp[0] == "" {
			continue
		}
		n, err := url.QueryUnescape(sp[0])
		if err != nil {
			continue
		}
		if n == name.Value {
			return &value.String{Value: sp[1]}, nil
		}
	}
	// includes not set value
	return &value.String{IsNotSet: true}, nil
}
