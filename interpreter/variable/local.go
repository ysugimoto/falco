package variable

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

type LocalVariables map[string]value.Value

func (v LocalVariables) Declare(name, valueType string) error {
	var val value.Value
	switch valueType {
	case "INTEGER":
		val = &value.Integer{}
	case "FLOAT":
		val = &value.Float{}
	case "BOOL":
		val = &value.Boolean{}
	case "BACKEND":
		val = &value.Backend{}
	case "IP":
		val = &value.IP{IsNotSet: true}
	case "STRING":
		val = &value.String{IsNotSet: true}
	case "RTIME":
		val = &value.RTime{}
	case "TIME":
		val = &value.Time{
			Value: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		}
	default:
		return errors.WithStack(fmt.Errorf(
			"Unexpected value type: %s", valueType,
		))
	}
	v[name] = val
	return nil
}

func (v LocalVariables) Get(name string) (value.Value, error) {
	if val, ok := v[name]; ok {
		return val, nil
	}
	return value.Null, errors.WithStack(fmt.Errorf(
		"Undefined variable %s", name,
	))
}

func (v LocalVariables) Set(name, operator string, val value.Value) error {
	left, ok := v[name]
	if !ok {
		return errors.WithStack(fmt.Errorf(
			"Undefined variable %s", name,
		))
	}
	if err := doAssign(left, operator, val); err != nil {
		return errors.WithStack(fmt.Errorf(
			"Failed to assign value to %s, %w", name, err,
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
		"Cannot add any value into local variable",
	))
}

func (v LocalVariables) Unset(name string) error {
	return errors.WithStack(fmt.Errorf(
		"Cannot unset local variable %s", name,
	))
}
