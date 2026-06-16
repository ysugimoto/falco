package variable

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

type LocalVariables map[string]value.Value

func (v LocalVariables) Declare(name, valueType string) error {
	val, err := value.Create(value.Type(valueType))
	if err != nil {
		return err
	}
	v[name] = val
	return nil
}

func (v LocalVariables) Get(name string) (value.Value, error) {
	if val, ok := v[name]; ok {
		return val, nil
	}
	return value.Null, errors.WithStack(fmt.Errorf(
		"undefined variable %s", name,
	))
}

func (v LocalVariables) Set(name, operator string, val value.Value) error {
	left, ok := v[name]
	if !ok {
		return errors.WithStack(fmt.Errorf(
			"undefined variable %s", name,
		))
	}
	if err := doAssign(left, operator, val); err != nil {
		return errors.WithStack(fmt.Errorf(
			"failed to assign value to %s, %w", name, err,
		))
	}

	// On local STRING variable assignment, always set notset to false even assign value is notset
	if str, ok := left.(*value.String); ok {
		str.IsNotSet = false
	}
	return nil
}

func (v LocalVariables) Add(name string, val value.Value) error {
	return errors.WithStack(fmt.Errorf(
		"cannot add any value into local variable",
	))
}

func (v LocalVariables) Unset(name string) error {
	return errors.WithStack(fmt.Errorf(
		"cannot unset local variable %s", name,
	))
}
