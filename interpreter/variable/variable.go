package variable

import (
	"fmt"
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
	// https://www.fastly.com/documentation/reference/vcl/variables/client-request/req-http/
	requestHttpHeaderRegex = regexp.MustCompile(`^req\.http\.(.+)`)
	// https://www.fastly.com/documentation/reference/vcl/variables/backend-request/bereq-http/
	backendRequestHttpHeaderRegex = regexp.MustCompile(`^bereq\.http\.(.+)`)
	// https://www.fastly.com/documentation/reference/vcl/variables/backend-response/beresp-http/
	backendResponseHttpHeaderRegex = regexp.MustCompile(`^beresp\.http\.(.+)`)
	// https://www.fastly.com/documentation/reference/vcl/variables/client-response/resp-http/
	responseHttpHeaderRegex = regexp.MustCompile(`^resp\.http\.(.+)`)
	// https://www.fastly.com/documentation/reference/vcl/variables/cache-object/obj-http/
	objectHttpHeaderRegex = regexp.MustCompile(`^obj\.http\.(.+)`)
	// https://www.fastly.com/documentation/reference/vcl/variables/rate-limiting/ratecounter-bucket-10s/
	rateCounterRegex = regexp.MustCompile(`ratecounter\.([^\.]+)\.(bucket|rate)\.([^\.]+)`)
	// https://www.fastly.com/documentation/reference/vcl/variables/miscellaneous/re-group/
	regexMatchedRegex = regexp.MustCompile(`re\.group\.([0-9]+)`)
	// https://www.fastly.com/documentation/reference/vcl/variables/backend-connection/backend-connections-open/
	backendConnectionsOpenRegex = regexp.MustCompile(`backend\.([^\.]+)\.connections_open`)
	// https://www.fastly.com/documentation/reference/vcl/variables/backend-connection/backend-connections-used/
	backendConnectionsUsedRegex = regexp.MustCompile(`backend\.([^\.]+)\.connections_used`)
	// https://www.fastly.com/documentation/reference/vcl/variables/backend-connection/backend-healthy/
	backendHealthyRegex = regexp.MustCompile(`backend\.([^\.]+)\.healthy`)
	// https://www.fastly.com/documentation/reference/vcl/variables/miscellaneous/director-healthy/
	directorHealthyRegex = regexp.MustCompile(`director\.([^\.]+)\.healthy`)
)

func doUpdateHash(left *value.String, operator string, right value.Value) error {
	if operator != "+=" {
		return errors.WithStack(fmt.Errorf("invalid operator, got %s", operator))
	}
	return assign.UpdateHash(left, right)
}

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

func lookupOverride(ctx *context.Context, name string) value.Value {
	if v, ok := ctx.OverrideVariables[name]; ok {
		return v
	}
	return nil
}
