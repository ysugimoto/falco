package function

import (
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

func assert[T string | int64 | bool | float64 | value.Type](left, right T, message string) (*value.Boolean, error) {
	ok := &value.Boolean{Value: left == right}
	if !ok.Value {
		if message != "" {
			return ok, errors.NewAssertionError(message)
		}
		return ok, errors.NewAssertionError(
			"Assertion error: expect=%v, actual=%v", left, right)
	}
	return ok, nil
}

func assert_not[T string | int64 | bool | float64 | value.Type](left, right T, message string) (*value.Boolean, error) {
	ok := &value.Boolean{Value: left != right}
	if ok.Value {
		if message != "" {
			return ok, errors.NewAssertionError(message)
		}
		return ok, errors.NewAssertionError(
			"Assertion error: expect=%v, actual=%v", left, right)
	}
	return ok, nil
}
