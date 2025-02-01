package function

import (
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

type assertable interface {
	string | int64 | bool | float64 | value.Type
}

func assert[T assertable](v value.Value, actual, expect T, message string) (*value.Boolean, error) {
	ok := &value.Boolean{Value: actual == expect}
	if !ok.Value {
		if message != "" {
			return ok, errors.NewAssertionError(v, "%s", message)
		}
		return ok, errors.NewAssertionError(v,
			"Assertion error: expect=%v, actual=%v", expect, actual)
	}
	return ok, nil
}

func assert_not[T assertable](v value.Value, actual, expect T, message string) (*value.Boolean, error) {
	ok := &value.Boolean{Value: actual != expect}
	if !ok.Value {
		if message != "" {
			return ok, errors.NewAssertionError(v, "%s", message)
		}
		return ok, errors.NewAssertionError(v,
			"Assertion error: expect=%v, actual=%v", expect, actual)
	}
	return ok, nil
}
