package interpreter

import (
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/function"
	"github.com/ysugimoto/falco/interpreter/operator"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/types"
)

func (i *Interpreter) IdentValue(val string, withCondition bool) (value.Value, error) {
	// Extra lookups identity - call additional ident finder if defined
	// This feature is implemented for testing, typically we do not use for interpreter working
	if i.IdentResolver != nil {
		if v := i.IdentResolver(val); v != nil {
			return v, nil
		}
	}

	if v, ok := i.ctx.Backends[val]; ok {
		return v, nil
	} else if v, ok := i.ctx.Acls[val]; ok {
		return v, nil
	} else if _, ok := i.ctx.Tables[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if _, ok := i.ctx.Gotos[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if _, ok := i.ctx.Penaltyboxes[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if _, ok := i.ctx.Ratecounters[val]; ok {
		return &value.Ident{Value: val, Literal: true}, nil
	} else if strings.HasPrefix(val, "var.") {
		if v, err := i.localVars.Get(val); err != nil {
			return value.Null, errors.WithStack(err)
		} else {
			return v, nil
		}
	} else if v, err := i.vars.Get(i.ctx.Scope, val); err != nil {
		if withCondition {
			return value.Null, nil
		} else {
			return value.Null, errors.WithStack(err)
		}
	} else {
		return v, nil
	}
}

// Evaluate expression
// withCondition boolean is special flag for evaluating expression,
// used for if condition, parenthesis wrapped expression.
// On if condition, prefix expression could use "!" prefix operator for null value.
//
// For example:
//
//	withCondition: true  -> if (!req.http.Foo) { ... } // Valid, req.http.Foo is nullable string but can be inverse as false
//	withCondition: false -> set var.bool = (!req.http.Foo); // Complicated but valid, "!" prefix operator could  use for right expression
//	withCondition: false -> set var.bool = !req.http.Foo;   // Invalid, bare "!" prefix operator could not use for right expression
func (i *Interpreter) ProcessExpression(exp ast.Expression, withCondition bool) (value.Value, error) {
	switch t := exp.(type) {
	// Underlying VCL type expressions
	case *ast.Ident:
		return i.IdentValue(t.Value, withCondition)
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
		var err error
		switch {
		case strings.HasSuffix(t.Value, "d"):
			num := strings.TrimSuffix(t.Value, "d")
			val, err = time.ParseDuration(num + "h")
			if err != nil {
				return nil, exception.Runtime(&exp.GetMeta().Token, "Failed to parse duration: %s", err)
			}
			val *= 24
		case strings.HasSuffix(t.Value, "y"):
			num := strings.TrimSuffix(t.Value, "y")
			val, err = time.ParseDuration(num + "h")
			if err != nil {
				return nil, exception.Runtime(&exp.GetMeta().Token, "Failed to parse duration: %s", err)
			}
			val *= 24 * 365
		default:
			val, err = time.ParseDuration(t.Value)
			if err != nil {
				return nil, exception.Runtime(&exp.GetMeta().Token, "Failed to parse duration: %s", err)
			}
		}
		return &value.RTime{Value: val, Literal: true}, nil

	// Combined expressions
	case *ast.PrefixExpression:
		return i.ProcessPrefixExpression(t, withCondition)
	case *ast.GroupedExpression:
		return i.ProcessGroupedExpression(t)
	case *ast.InfixExpression:
		if t.Operator == "+" {
			return i.ProcessStringConcatInfixExpression(t)
		}
		return i.ProcessInfixExpression(t, withCondition)
	case *ast.IfExpression:
		return i.ProcessIfExpression(t)
	case *ast.FunctionCallExpression:
		return i.ProcessFunctionCallExpression(t, withCondition)
	default:
		return value.Null, exception.Runtime(&exp.GetMeta().Token, "Undefined expression found")
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
			return &value.Boolean{Value: !t.Value}, nil
		case *value.String:
			// If withCondition is enabled, STRING could be converted to BOOL
			if !withCondition {
				return value.Null, errors.WithStack(
					exception.Runtime(&exp.GetMeta().Token, `Unexpected "!" prefix operator for %v`, v),
				)
			}
			if t.IsNotSet {
				return &value.Boolean{Value: true}, nil
			}
			return &value.Boolean{Value: false}, nil
		default:
			return value.Null, errors.WithStack(
				exception.Runtime(&exp.GetMeta().Token, `Unexpected "!" prefix operator for %v`, v),
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
				exception.Runtime(&exp.GetMeta().Token, `Unexpected "-" prefix operator for %v`, v),
			)
		}
	case "+":
		// I'm wondering what calculate to?
		return v, nil
	default:
		return value.Null, errors.WithStack(
			exception.Runtime(&exp.GetMeta().Token, "Unexpected prefix operator: %s", exp.Operator),
		)
	}
}

func (i *Interpreter) ProcessPostfixExpression(exp *ast.PostfixExpression) (value.Value, error) {
	v, err := i.ProcessExpression(exp.Left, false)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}

	if exp.Operator != "%" {
		return value.Null, errors.WithStack(
			exception.Runtime(&exp.GetMeta().Token, "Unexpected postfix operator: %s", exp.Operator),
		)
	}
	t, ok := v.(*value.Integer)
	if !ok {
		return value.Null, errors.WithStack(
			exception.Runtime(&exp.GetMeta().Token, `Unexpected "%%" postfix operator for %v`, v),
		)
	}
	return t, nil
}

func (i *Interpreter) ProcessGroupedExpression(exp *ast.GroupedExpression) (value.Value, error) {
	v, err := i.ProcessExpression(exp.Right, true)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	return v, nil
}

func (i *Interpreter) ProcessIfExpression(exp *ast.IfExpression) (value.Value, error) {
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
		if !t.IsNotSet {
			return i.ProcessExpression(exp.Consequence, false)
		}
	default:
		if cond == value.Null {
			return i.ProcessExpression(exp.Alternative, false)
		}
		return value.Null, exception.Runtime(&exp.GetMeta().Token, "If condition returns not boolean")
	}

	return i.ProcessExpression(exp.Alternative, false)
}

func (i *Interpreter) ProcessFunctionCallExpression(exp *ast.FunctionCallExpression, withCondition bool) (value.Value, error) {
	if sub, ok := i.ctx.SubroutineFunctions[exp.Function.Value]; ok {
		if len(exp.Arguments) > 0 {
			return value.Null, exception.Runtime(
				&exp.GetMeta().Token,
				"Function subroutine %s could not accept any arguments",
				exp.Function.Value,
			)
		}
		// If mocked functional subroutine found, use it
		if mocked, ok := i.ctx.MockedFunctioncalSubroutines[exp.Function.Value]; ok {
			sub = mocked
		}
		if _, ok := types.ValueTypeMap[sub.ReturnType.Value]; !ok {
			return value.Null, exception.Runtime(
				&sub.GetMeta().Token,
				"subroutine %s has invalid return type %s",
				sub.Name,
				sub.ReturnType,
			)
		}
		// Functional subroutine may change status
		v, _, err := i.ProcessFunctionSubroutine(sub, DebugPass)
		if err != nil {
			return v, errors.WithStack(err)
		}
		return v, nil
	}
	fn, err := function.Exists(i.ctx.Scope, exp.Function.Value)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	args := make([]value.Value, len(exp.Arguments))
	for j := range exp.Arguments {
		if fn.IsIdentArgument(j) {
			// If function accepts ID type, pass the string as Ident value without processing expression.
			// This is because some function uses collection value like req.http.Cookie as ID type,
			// But the processor passes *value.String as primitive value normally.
			// In order to treat collection value inside, ensure ident argument is treated as correspond types.
			if ident, ok := exp.Arguments[j].(*ast.Ident); ok {
				args[j] = &value.Ident{Value: ident.Value}
			} else {
				return value.Null, errors.WithStack(
					exception.Runtime(
						&exp.Arguments[j].GetMeta().Token,
						"Function %s of %d argument must be an Ident", exp.Function.Value, j,
					),
				)
			}
		} else {
			a, err := i.ProcessExpression(exp.Arguments[j], withCondition)
			if err != nil {
				return value.Null, errors.WithStack(err)
			}
			args[j] = a
		}
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

	var result value.Value
	var opErr error

	switch exp.Operator {
	case "==":
		result, opErr = operator.Equal(left, right)
	case "!=":
		result, opErr = operator.NotEqual(left, right)
	case ">":
		result, opErr = operator.GreaterThan(left, right)
	case "<":
		result, opErr = operator.LessThan(left, right)
	case ">=":
		result, opErr = operator.GreaterThanEqual(left, right)
	case "<=":
		result, opErr = operator.LessThanEqual(left, right)
	case "~":
		result, opErr = operator.Regex(i.ctx, left, right)
	case "!~":
		result, opErr = operator.NotRegex(i.ctx, left, right)
	case "||":
		result, opErr = operator.LogicalOr(left, right)
	case "&&":
		result, opErr = operator.LogicalAnd(left, right)
	default:
		return value.Null, errors.WithStack(
			exception.Runtime(&exp.GetMeta().Token, "Unexpected infix operator: %s", exp.Operator),
		)
	}

	if opErr != nil {
		return value.Null, errors.WithStack(
			exception.Runtime(&exp.GetMeta().Token, "%s", opErr.Error()),
		)
	}

	return result, nil
}

// InfixExpression process, but special case for string concatenation.
// string cocatenation has special type checking rule.
// left and right expression must be following expressions:
// - STRING                  - both literal and ident
// - IDENT                   - common variables like req.*, var.*, now, etc
// - PrefixExpression        - the operator must be "+"
// - InfixExpression(nested) - same rule for left and right expression, and operator must be "+"
// - FunctionCallExpression  - return value must be STRING
// - IfExpression            - return value must be STRING
//
// Other expressions (e.g GroupedExpression) is invalid. For example:
// set req.http.SomeHeader = "a" + "b" + "c";   // valid
// set req.http.SomeHeader = "a" + ("b" + "c"); // invalid
//
// And we need to consider about "time calculation" - calculate between TIME and RTIME - as following rules:
// 1. RTIME literal with explicit plus or minus sign should be accepted for concatenating to previous TIME expression
// 2. And previous TIME expression must be an IDENT - invalid for return type of FunctionCallExpression like std.time()
//
// Above two rules are satisfied, if should be "time calculation", add RTIME duration to the TIME.
// For example syntaxes:
// set req.http.Foo = now + 5m;                             // valid, time calculation(plus) between now(TIME) and 5m(RTIME literal)
// set req.http.Foo = now - 5m;                             // valid, time calculation(minus) between now(TIME) and 5m(RTIME literal)
// set req.http.Foo = now + var.someRTime;                  // invalid, plus sign will be time calculation but accept only literal
// set req.http.Foo = now var.someRTime;                    // valid, string concatenation
// set req.http.Foo = now 5m;                               // invalid, time calculate syntax error
// set req.http.Foo = std.time("xxx", now) + 5m;            // invalid, left expression is TIME type but not an ident
// set req.http.Foo = std.time("xxx", now) + var.someRTime; // valid, string concatenation
//
// See Fastly fiddle: https://fiddle.fastly.dev/fiddle/befec89e
// nolint: gocognit
func (i *Interpreter) ProcessStringConcatInfixExpression(exp *ast.InfixExpression) (value.Value, error) {
	var series []*series

	left, err := i.toSeriesExpression(exp.Left)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	series = append(series, left...)

	right, err := i.toSeriesExpression(exp.Right)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	if exp.Explicit {
		right[0].Operator = exp.Operator
	}
	series = append(series, right...)

	var rv value.Value = &value.String{}
	var opErr error

	for idx := 0; idx < len(series); idx++ {
		s := series[idx]
		cv, err := i.ProcessExpression(s.Expression, false)
		if err != nil {
			return value.Null, errors.WithStack(err)
		}

		switch s.Expression.(type) {
		case *ast.String:
			rv, opErr = operator.Concat(rv, cv)
			if opErr != nil {
				return value.Null, errors.WithStack(err)
			}
		case *ast.IfExpression:
			if cv.Type() != value.StringType {
				return value.Null, exception.Runtime(
					&s.Expression.GetMeta().Token,
					"Cannot use %s type for string concatenation",
					cv.Type(),
				)
			}
			rv, opErr = operator.Concat(rv, cv)
			if opErr != nil {
				return value.Null, errors.WithStack(err)
			}
		case *ast.FunctionCallExpression:
			// Fiddle: https://fiddle.fastly.dev/fiddle/e71a005f
			if cv.Type() == value.BackendType || cv.Type() == value.AclType {
				return value.Null, exception.Runtime(
					&s.Expression.GetMeta().Token,
					"Cannot use %s type for string concatenation",
					cv.Type(),
				)
			}
			rv, opErr = operator.Concat(rv, cv)
			if opErr != nil {
				return value.Null, errors.WithStack(err)
			}
		case *ast.Ident:
			switch cv.Type() {
			case value.StringType:
				rv, opErr = operator.Concat(rv, cv)
				if opErr != nil {
					return value.Null, errors.WithStack(err)
				}
				continue
			case value.TimeType:
				// If ident value type is TIME, check the next expression is RTIME literal.
				// If so, it calculates as time calculation.
				if idx+1 < len(series)-1 {
					next := series[idx+1]
					if _, ok := next.Expression.(*ast.RTime); ok {
						nv, err := i.ProcessExpression(next.Expression, false)
						if err != nil {
							return value.Null, errors.WithStack(err)
						}
						cv, opErr = operator.TimeCalculation(cv, nv, next.Operator)
						if opErr != nil {
							return value.Null, errors.WithStack(err)
						}
						// String concat with left and time-calculated value (TIME type)
						rv, opErr = operator.Concat(rv, cv)
						if opErr != nil {
							return value.Null, errors.WithStack(err)
						}
						// Next RTime is consumed, increment index
						idx++
						continue
					}
				}
			case value.RTimeType:
				// If expression is RTIME literal, follwing condition must be satisfied:
				// - previous expression is IDENT and the value if TIME type
				// - explicitly calculation sign ("+" or "-") must be present
				if s.Operator == "+" || s.Operator == "-" {
					if idx-1 >= 0 {
						prev := series[idx-1]
						v, err := i.ProcessExpression(prev.Expression, false)
						if err != nil {
							return value.Null, errors.WithStack(err)
						}
						if v.Type() == value.TimeType {
							return value.Null, exception.Runtime(
								&s.Expression.GetMeta().Token,
								"Cannot use RTIME type for string concatenation",
							)
						}
					}
				}
			}
			rv, opErr = operator.Concat(rv, cv)
			if opErr != nil {
				return value.Null, errors.WithStack(err)
			}
		default:
			return value.Null, exception.Runtime(
				&s.Expression.GetMeta().Token,
				"Cannot use %s type for string concatenation",
				cv.Type(),
			)
		}
	}

	return rv, nil
}

func (i *Interpreter) toSeriesExpression(expr ast.Expression) ([]*series, error) {
	switch t := expr.(type) {
	case *ast.Ident:
		// If expression is ident, it must be a variable
		// e.g req.http.Header, var.declaredVariable
		if strings.HasPrefix(t.Value, "var.") {
			if _, err := i.localVars.Get(t.Value); err != nil {
				return nil, errors.WithStack(err)
			}
		} else if _, err := i.vars.Get(i.ctx.Scope, t.Value); err != nil {
			return nil, errors.WithStack(err)
		}
	case *ast.PrefixExpression:
		if t.Operator != "+" && t.Operator != "-" {
			return nil, exception.Runtime(
				&expr.GetMeta().Token,
				"Cannot use %s operator for string concatenation",
				t.Operator,
			)
		}
		s, err := i.toSeriesExpression(t.Right)
		if err != nil {
			return nil, err
		}
		s[0].Operator = t.Operator
		return s, nil
	case *ast.GroupedExpression:
		return nil, exception.Runtime(&expr.GetMeta().Token, "Cannot use GroupedExpression for string concatenation")
	case *ast.InfixExpression:
		if t.Operator != "+" {
			return nil, exception.Runtime(
				&expr.GetMeta().Token,
				"Cannot use %s operator for string concatenation",
				t.Operator,
			)
		}
		var s []*series
		left, err := i.toSeriesExpression(t.Left)
		if err != nil {
			return nil, err
		}
		s = append(s, left...)

		right, err := i.toSeriesExpression(t.Right)
		if err != nil {
			return nil, err
		}
		if t.Explicit {
			right[0].Operator = t.Operator
		}
		s = append(s, right...)
		return s, nil
	}

	// Concatenatable expression
	return []*series{
		{Expression: expr},
	}, nil
}
