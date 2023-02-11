package errors

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/ysugimoto/falco/interpreter/value"
)

func New(name, format string, args ...interface{}) error {
	return errors.WithStack(fmt.Errorf("["+name+"] "+format, args...))
}

func NotImplemented(name string) error {
	return New(name, "Not implemented")
}

func ArgumentMustEmpty(name string, args []value.Value) error {
	return New(name, "Could not accept any arguments but %d provided", len(args))
}

func ArgumentNotEnough(name string, expects int, args []value.Value) error {
	return New(name, "Expects %d arguments but %d provided", expects, len(args))
}

func ArgumentNotInRange(name string, min, max int, args []value.Value) error {
	return New(name, "Expects between %d and %d arguments but %d argument provided", min, max, len(args))
}

func TypeMismatch(name string, num int, expects, actual value.Type) error {
	return New(name, "Argument %d expects %s type but %s provided", num, expects, actual)
}
