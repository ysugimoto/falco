package interpreter

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/operator"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/function"
)

func (i *Interpreter) IdentValue(val string) (value.Value, error) {
	if v, ok := i.ctx.Backends[val]; ok {
		return &value.Backend{Value: v, Literal: true}, nil
	} else if v, ok := i.ctx.Acls[val]; ok {
		return &value.Acl{Value: v, Literal: true}, nil
	} else if _, ok := i.ctx.Tables[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if _, ok := i.ctx.Gotos[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if _, ok := i.ctx.Penaltyboxes[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if _, ok := i.ctx.Ratecounters[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if strings.HasPrefix(val, "var.") {
		if v, err := i.localVars.Get(i.scope, val); err != nil {
			return value.Null, errors.WithStack(err)
		} else {
			return  v, nil
		}
	} else if v, err := i.vars.Get(i.scope, val); err != nil {
		return value.Null, errors.WithStack(err)
	} else {
		return v, nil
	}
}

// Evaluate expression
// withCondition boolean is special flag for evaluating expression, used for if condition.
// On if condition, prefix expression could use "!" prefix operator for null value.
// For example:
//   withCondition: true  -> if (!req.http.Foo) { ... } // Valid, req.http.Foo is nullable string but can be inverse as false
//   withCondition: false -> set var.bool = (!req.http.Foo); // Complicated but valid, "!" prefix operator could  use for right expression
//   withCondition: false -> set var.bool = !req.http.Foo;   // Invalid, bare "!" prefix operator could not use for right expression
func (i *Interpreter) ProcessExpression(exp ast.Expression, withCondition bool) (value.Value, error) {
	switch t := exp.(type) {
	// Underlying VCL type expressions
	case *ast.Ident:
		return i.IdentValue(t.Value)
	case *ast.IP:
		return &value.IP{Value: net.ParseIP(t.Value), Literal: true}, nil
	case *ast.Boolean:
		return &value.Boolean{Value: t.Value, Literal: true}, nil
	case *ast.Integer:
		return &value.Integer{Value: t.Value, Literal: true}, nil
	case *ast.String:
		return &value.String{Value: t.Value, Literal: true}, nil
	case *ast.Float:
		return &value.Float{Value: t.Value, Literal: true}, nil
	case *ast.RTime:
		var val time.Duration
		switch {
		case strings.HasSuffix(t.Value, "d"):
			num := strings.TrimSuffix(t.Value, "d")
			val, _ = time.ParseDuration(num + "h")
			val *= 24
		case strings.HasSuffix(t.Value, "y"):
			num := strings.TrimSuffix(t.Value, "y")
			val, _ = time.ParseDuration(num + "h")
			val *= 24 * 365
		default:
			val, _ = time.ParseDuration(t.Value)
		}
		return &value.RTime{Value: val, Literal: true}, nil

	// Combinated expressions
	case *ast.PrefixExpression:
		return i.ProcessPrefixExpression(t, withCondition)
	case *ast.GroupedExpression:
		return i.ProcessGroupedExpression(t)
	case *ast.InfixExpression:
		return i.ProcessInfixExpression(t, withCondition)
	case *ast.IfExpression:
		return i.ProcessIfExpression(t)
	case *ast.FunctionCallExpression:
		return i.ProcessFunctionCallExpression(t, withCondition)
	default:
		return value.Null, errors.WithStack(fmt.Errorf("Undefined expression"))
	}
}

func (i *Interpreter) ProcessPrefixExpression(exp *ast.PrefixExpression, withCondition bool) (value.Value, error) {
	v, err := i.ProcessExpression(exp.Right, withCondition)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	switch exp.Operator {
	case "!":
		switch t := v.(type) {
		case *value.Boolean:
			t.Value = !t.Value
			return t, nil
		case *value.String:
			// If withCondition is enabled, STRING could be convert to BOOL
			if !withCondition {
				return value.Null, errors.WithStack(
					fmt.Errorf(`Unexpected "!" prefix operator for %v`, v),
				)
			}
			return &value.Boolean{Value: t.Value == ""}, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf(`Unexpected "!" prefix operator for %v`, v),
			)
		}
	case "-":
		switch t := v.(type) {
		case *value.Integer:
			t.Value = -t.Value
			return t, nil
		case *value.Float:
			t.Value = -t.Value
			return t, nil
		case *value.RTime:
			t.Value = -t.Value
			return t, nil
		default:
			return value.Null, errors.WithStack(
				fmt.Errorf(`Unexpected "-" prefix operator for %v`, v),
			)
		}
	case "+":
		// I'm wondering what calculate to?
		return v, nil
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Unexpected prefix operator: %s", exp.Operator),
		)
	}
}

func (i *Interpreter) ProcessGroupedExpression(exp *ast.GroupedExpression) (value.Value, error) {
	v, err := i.ProcessExpression(exp.Right, true)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	return v, nil
}

func (i *Interpreter) ProcessIfExpression(exp *ast.IfExpression) (value.Value, error) {
	// if
	cond, err := i.ProcessExpression(exp.Condition, true)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}

	switch t := cond.(type) {
	case *value.Boolean:
		if t.Value {
			return i.ProcessExpression(exp.Consequence, false)
		}
	case *value.String:
		if t.Value != "" {
			return i.ProcessExpression(exp.Consequence, false)
		}
	default:
		return value.Null, fmt.Errorf("If condition is not boolean")
	}

	// else
	return i.ProcessExpression(exp.Alternative, false)
}

func (i *Interpreter) ProcessFunctionCallExpression(exp *ast.FunctionCallExpression, withCondition bool) (value.Value, error) {
	fn, err := function.Exists(i.scope, exp.Function.Value)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	args := make([]value.Value, len(exp.Arguments))
	for j := range exp.Arguments {
		a, err := i.ProcessExpression(exp.Arguments[j], withCondition)
		if err != nil {
			return value.Null, errors.WithStack(err)
		}
		args[j] = a
	}
	return fn.Call(i.ctx, args...)
}

func (i *Interpreter) ProcessInfixExpression(exp *ast.InfixExpression, withCondition bool) (value.Value, error) {
	left, err := i.ProcessExpression(exp.Left, withCondition)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	right, err := i.ProcessExpression(exp.Right, withCondition)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}

	switch exp.Operator {
	case "==":
		return operator.Equal(left, right)
	case "!=":
		return operator.NotEqual(left, right)
	case ">":
		return operator.GreaterThan(left, right)
	case "<":
		return operator.LessThan(left, right)
	case ">=":
		return operator.GreaterThanEqual(left, right)
	case "<=":
		return operator.LessThanEqual(left, right)
	case "~":
		return operator.Regex(i.ctx, left, right)
	case "!~":
		return operator.NotRegex(i.ctx, left, right)
	case "||":
		return operator.LogicalAnd(left, right)
	case "&&":
		return operator.LogicalOr(left, right)
	// "+" means string concatenation
	case "+":
		return operator.Concat(left, right)
	default:
		return value.Null, errors.WithStack(
			fmt.Errorf("Unexpected infix operator: %s", exp.Operator),
		)
	}
}
