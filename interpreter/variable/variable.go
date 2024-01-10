package variable

import (
	"regexp"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/assign"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

type Variable interface {
	Get(context.Scope, string) (value.Value, error)
	Set(context.Scope, string, string, value.Value) error
	Add(context.Scope, string, value.Value) error
	Unset(context.Scope, string) error
}

var (
	requestHttpHeaderRegex         = regexp.MustCompile(`^req\.http\.(.+)`)
	backendRequestHttpHeaderRegex  = regexp.MustCompile(`^bereq\.http\.(.+)`)
	backendResponseHttpHeaderRegex = regexp.MustCompile(`^beresp\.http\.(.+)`)
	responseHttpHeaderRegex        = regexp.MustCompile(`^resp\.http\.(.+)`)
	objectHttpHeaderRegex          = regexp.MustCompile(`^obj\.http\.(.+)`)
	rateCounterRegex               = regexp.MustCompile(`ratecounter\.([^\.]+)\.(.+)`)
	regexMatchedRegex              = regexp.MustCompile(`re\.group\.([0-9]+)`)
)

func doAssign(left value.Value, operator string, right value.Value) (value.Value, error) {
	switch operator {
	case "+=":
		if err := assign.Addition(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "-=":
		if err := assign.Subtraction(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "*=":
		if err := assign.Multiplication(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "/=":
		if err := assign.Division(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "%=":
		if err := assign.Remainder(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "|=":
		if err := assign.BitwiseOR(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "&=":
		if err := assign.BitwiseAND(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "^=":
		if err := assign.BitwiseXOR(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "<<=":
		if err := assign.LeftShift(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case ">>=":
		if err := assign.RightShift(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "rol=":
		if err := assign.LeftRotate(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "ror=":
		if err := assign.RightRotate(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "||=":
		if err := assign.LogicalOR(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	case "&&=":
		if err := assign.LogicalAND(left, right); err != nil {
			return nil, errors.WithStack(err)
		}
		return left, nil
	default: // "="
		// Important: Assign fucntion returns assigned Value.
		// This is because value type would be changed after assignment (e.g String -> LenientString)
		// To accept this change, return new value
		return assign.Assign(left, right.Copy())
	}
}

func coerceString(v value.Value) *value.String {
	if s, ok := v.(*value.LenientString); ok {
		return s.ToString()
	}
	return value.Unwrap[*value.String](v)
}
