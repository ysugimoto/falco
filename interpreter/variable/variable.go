package variable

import (
	"regexp"

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

func doAssign(left value.Value, operator string, right value.Value) error {
	switch operator {
	case "+=":
		return assign.Addition(left, right)
	case "-=":
		return assign.Subtraction(left, right)
	case "*=":
		return assign.Multiplication(left, right)
	case "/=":
		return assign.Division(left, right)
	case "%=":
		return assign.Remainder(left, right)
	case "|=":
		return assign.BitwiseOR(left, right)
	case "&=":
		return assign.BitwiseAND(left, right)
	case "^=":
		return assign.BitwiseXOR(left, right)
	case "<<=":
		return assign.LeftShift(left, right)
	case ">>=":
		return assign.RightShift(left, right)
	case "rol=":
		return assign.LeftRotate(left, right)
	case "ror=":
		return assign.RightRotate(left, right)
	case "||=":
		return assign.LogicalOR(left, right)
	case "&&=":
		return assign.LogicalAND(left, right)
	default: // "="
		return assign.Assign(left, right.Copy())
	}
}
