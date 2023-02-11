package errors

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/ysugimoto/falco/interpreter/value"
)

func NotImplemented(name string) error {
	return errors.WithStack(
		fmt.Errorf("Builtin function %s is not implemented", name),
	)
}

func ArgumentMustEmpty(name string, args []value.Value) error {
	return errors.WithStack(
		fmt.Errorf(
			"Builtin function %s could not accept any arguments but %d provided",
			name, len(args),
		),
	)
}

func ArgumentNotEnough(name string, expects int, args []value.Value) error {
	return errors.WithStack(
		fmt.Errorf(
			"Builtin function %s expects %d arguments but %d provided",
			name, expects, len(args),
		),
	)
}

func ArgumentNotInRange(name string, min, max int, args []value.Value) error {
	return errors.WithStack(
		fmt.Errorf(
			"Builtin function %s expects between %d and %d arguments but %d argument provided",
			name, min, max, len(args),
		),
	)
}

func TypeMismatch(name string, num int, expects, actual value.Type) error {
	return errors.WithStack(
		fmt.Errorf(
			"Builtin function %s argument %d expects %s type but %s provided",
			name, num, expects, actual,
		),
	)
}
