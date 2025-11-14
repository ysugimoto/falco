package linter

import (
	"fmt"
	"net"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/linter/context"
	"github.com/ysugimoto/falco/types"
	regexp "go.elara.ws/pcre"
)

func (l *Linter) lintIP(exp *ast.IP) types.Type {
	// validate valid IP string
	if v := net.ParseIP(exp.Value); v == nil {
		err := &LintError{
			Severity: ERROR,
			Token:    exp.GetMeta().Token,
			Message:  fmt.Sprintf(`"%s" is invalid IP string`, exp.Value),
		}
		l.Error(err.Match(VALID_IP))
	}
	return types.IPType
}

func (l *Linter) lintBoolean(exp *ast.Boolean) types.Type {
	return types.BoolType
}

func (l *Linter) lintInteger(exp *ast.Integer) types.Type {
	return types.IntegerType
}

func (l *Linter) lintString(exp *ast.String) types.Type {
	return types.StringType
}

func (l *Linter) lintFloat(exp *ast.Float) types.Type {
	return types.FloatType
}

func (l *Linter) lintRTime(exp *ast.RTime) types.Type {
	return types.RTimeType
}

func (l *Linter) lintPrefixExpression(exp *ast.PrefixExpression, ctx *context.Context) types.Type {
	right := l.lint(exp.Right, ctx)
	if right == types.NeverType {
		return right
	}
	switch exp.Operator {
	case "!":
		// The bang operator case is pre-checked in isValidConditionExpression and isValidStatmentExpression
		return right
	case "-":
		if !expectType(right, types.IntegerType, types.FloatType, types.RTimeType) {
			l.Error(InvalidTypeExpression(
				exp.GetMeta(), right, types.IntegerType, types.FloatType, types.RTimeType,
			))
		}
		return right
	case "+":
		if !expectType(right, types.StringType, types.IntegerType, types.FloatType, types.RTimeType, types.BoolType) {
			l.Error(InvalidTypeExpression(
				exp.GetMeta(), right, types.StringType, types.IntegerType, types.FloatType, types.RTimeType, types.BoolType,
			))
		}
		return right
	}

	return types.NeverType
}

func (l *Linter) lintPostfixExpression(exp *ast.PostfixExpression, ctx *context.Context) types.Type {
	left := l.lint(exp.Left, ctx)
	if left == types.NeverType {
		return left
	}
	if exp.Operator != "%" { // % is the only postfix operator
		return types.NeverType
	}
	if !expectType(left, types.IntegerType) {
		l.Error(InvalidTypeExpression(exp.GetMeta(), left, types.IntegerType))
	}
	return left
}

func (l *Linter) lintGroupedExpression(exp *ast.GroupedExpression, ctx *context.Context) types.Type {
	right := l.lint(exp.Right, ctx)
	return right
}

// InfixExpression linting, but special case for string concatenation.
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
func (l *Linter) lintStringConcatInfixExpression(exp *ast.InfixExpression, ctx *context.Context) types.Type {
	var series []*Series

	// Convert to expression series
	left, err := toSeriesExpressions(exp.Left, ctx)
	if err != nil {
		l.Error(err.Match(OPERATOR_CONDITIONAL))
		return types.NeverType
	}
	series = append(series, left...)

	right, err := toSeriesExpressions(exp.Right, ctx)
	if err != nil {
		l.Error(err.Match(OPERATOR_CONDITIONAL))
		return types.NeverType
	}
	if exp.Explicit {
		right[0].Operator = exp.Operator
	}
	series = append(series, right...)

	// Note:
	// VCL variables accepts other types with implicit type conversion as following:
	// IDENT   -> point value
	// STRING  -> raw string
	// INTEGER -> stringify
	// FLOAT   -> stringify
	// IP      -> stringify
	// TIME    -> stringify (GMT string)
	// RTIME   -> stringify (Float value of duration)
	// BOOL    -> 0 (false) or 1 (true)
	// And any literals except STRING could not accept.
	ct := types.NeverType
	for i := 0; i < len(series); i++ {
		s := series[i]
		nt := l.lint(s.Expression, ctx)
		meta := s.Expression.GetMeta()

		switch t := s.Expression.(type) {
		case *ast.String:
			break
		case *ast.IfExpression:
			switch nt {
			case types.AclType, types.BackendType:
				l.Error(InvalidStringConcatenation(meta, nt.String()).Match(OPERATOR_CONDITIONAL))
			case types.StringType:
				break
			default:
				// If consequence and alternative expression is not STRING type (e.g. INTEGER, FLOAT, BOOL) in if expression,
				// The expression must not be a literal
				switch {
				case isConstantExpression(t.Consequence):
					l.Error(InvalidStringConcatenation(t.Consequence.GetMeta(), nt.String()).Match(OPERATOR_CONDITIONAL))
				case isConstantExpression(t.Alternative):
					l.Error(InvalidStringConcatenation(t.Alternative.GetMeta(), nt.String()).Match(OPERATOR_CONDITIONAL))
				default:
					l.Error(ImplicitTypeConversion(meta, nt, types.StringType))
				}
			}
		case *ast.FunctionCallExpression:
			// If function call expression, arbitrary type except ACL and BACKEND can be used.
			// However, without STRING type (e.g INTEGER, FLOAT) will be implicit type conversion
			switch nt {
			case types.AclType, types.BackendType:
				l.Error(InvalidStringConcatenation(meta, nt.String()).Match(OPERATOR_CONDITIONAL))
			case types.StringType:
				break
			default:
				l.Error(ImplicitTypeConversion(meta, nt, types.StringType))
			}
		case *ast.Ident:
			switch nt {
			case types.StringType:
				goto OUT
			case types.TimeType:
				// If ident value type is TIME, check the next expression is RTIME literal.
				// If so, it is time addition so suppress ImplicitTypeConversionError.
				if i+1 < len(series)-1 {
					next := series[i+1]
					if _, ok := next.Expression.(*ast.RTime); ok {
						goto OUT
					}
				}
			case types.RTimeType:
				// If ident value type is RTIME with plus sign, previous type must no TIME type (string concatenation)
				if s.Operator == "+" || s.Operator == "-" {
					if ct == types.TimeType {
						l.Error(InvalidStringConcatenation(meta, "RTIME").Match(OPERATOR_CONDITIONAL))
						goto OUT
					}
				}
			}
			l.Error(ImplicitTypeConversion(meta, nt, types.StringType))
		case *ast.RTime:
			// If expression is RTIME literal, follwing condition must be satisfied:
			// - previous expression is IDENT and the value if TIME type
			// - explicitly calculation sign ("+" or "-") must be present
			if ct == types.TimeType {
				if s.Operator == "+" || s.Operator == "-" {
					if _, ok := series[i-1].Expression.(*ast.Ident); ok {
						// Valid for time addition but we will report as WARNING
						l.Error(TimeCalculatation(meta).Match(TIME_CALCULATION))
						goto OUT
					}
				}
			}
			l.Error(InvalidStringConcatenation(meta, "RTIME").Match(OPERATOR_CONDITIONAL))
		default:
			l.Error(InvalidStringConcatenation(meta, nt.String()).Match(OPERATOR_CONDITIONAL))
		}
	OUT:
		ct = nt
	}

	return types.StringType
}

func (l *Linter) lintInfixExpression(exp *ast.InfixExpression, ctx *context.Context) types.Type {
	left := l.lint(exp.Left, ctx)
	if left == types.NeverType {
		return left
	}
	right := l.lint(exp.Right, ctx)
	if right == types.NeverType {
		return right
	}

	// Opereator should be comparison operator.
	switch exp.Operator {
	case "==", "!=":
		// Cast req.backend to standard backend type for comparisons
		// Fiddle demonstrating these comparisons are valid:
		// https://fiddle.fastly.dev/fiddle/06865e2d
		if left == types.ReqBackendType {
			left = types.BackendType
		}
		if right == types.ReqBackendType {
			right = types.BackendType
		}
		// Equal operator could compare any types but both left and right type must be the same.
		if left != right {
			l.Error(InvalidTypeComparison(exp.GetMeta(), left, right).Match(OPERATOR_CONDITIONAL))
		}
		return types.BoolType
	case ">", ">=", "<", "<=":
		// Greater/Less than operator only could compare with INTEGER, FLOAT, or RTIME type
		switch left {
		case types.IntegerType:
			// When left type is INTEGER, right type must be INTEGER or RTIME
			if !expectType(right, types.IntegerType, types.RTimeType) {
				l.Error(InvalidTypeExpression(exp.GetMeta(), right, types.IntegerType, types.RTimeType).Match(OPERATOR_CONDITIONAL))
			}
		case types.FloatType, types.RTimeType:
			// When left type is FLOAT or RTIME, right type must be INTEGER or FLOAT or RTIME
			if !expectType(right, types.IntegerType, types.FloatType, types.RTimeType) {
				l.Error(InvalidTypeExpression(exp.GetMeta(), right, types.IntegerType, types.FloatType, types.RTimeType).Match(OPERATOR_CONDITIONAL))
			}
		default:
			l.Error(InvalidTypeExpression(exp.GetMeta(), left, types.IntegerType, types.FloatType, types.RTimeType).Match(OPERATOR_CONDITIONAL))
		}
		return types.BoolType
	case "~", "!~":
		// Regex operator could compare only STRING, IP or ACL type
		if !expectType(left, types.StringType, types.IPType) {
			l.Error(InvalidTypeExpression(exp.GetMeta(), left, types.StringType, types.IPType, types.AclType).Match(OPERATOR_CONDITIONAL))
		} else if !expectType(right, types.StringType, types.AclType, types.RegexType) {
			l.Error(InvalidTypeExpression(exp.GetMeta(), right, types.StringType, types.RegexType).Match(OPERATOR_CONDITIONAL))
		}
		if expectType(right, types.StringType) && !isLiteralExpression(exp.Right) {
			l.Error(&LintError{
				Severity: ERROR,
				Token:    exp.Right.GetMeta().Token,
				Message:  "Regex patterns must be string literals.",
			})
		}
		// And, if right expression is STRING, regex must be valid
		if v, ok := exp.Right.(*ast.String); ok {
			if _, err := regexp.Compile(v.Value); err != nil {
				err := &LintError{
					Severity: ERROR,
					Token:    exp.Right.GetMeta().Token,
					Message:  "regex string is invalid, " + err.Error(),
				}
				l.Error(err)
			}
		}
		return types.BoolType
	case "&&", "||":
		// AND / OR operator compares left and right with truthy or falsy
		return types.BoolType
	default:
		return types.NeverType
	}
}

func (l *Linter) lintIfExpression(exp *ast.IfExpression, ctx *context.Context) types.Type {
	l.lintIfCondition(exp.Condition, ctx)
	pushRegexGroupVars(exp.Condition, ctx)

	if isConstantExpression(exp.Consequence) {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Consequence.GetMeta().Token,
			Message:  "Cannot use constant literal in If expression consequence",
		})
	}
	left := l.lint(exp.Consequence, ctx)

	if isConstantExpression(exp.Alternative) {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Alternative.GetMeta().Token,
			Message:  "Cannot use constant literal in If expression alternative",
		})
	}
	right := l.lint(exp.Alternative, ctx)

	if left != right {
		l.Error(&LintError{
			Severity: WARNING,
			Token:    exp.GetMeta().Token,
			Message:  "If expression returns different type between consequence and alternative",
		})
	}
	return left
}

func (l *Linter) lintFunctionCallExpression(exp *ast.FunctionCallExpression, ctx *context.Context) types.Type {
	// Check if this is a user-defined function subroutine (with return type)
	if sub, ok := ctx.Subroutines[exp.Function.Value]; ok && sub.Decl.ReturnType != nil {
		params := sub.Decl.Parameters
		args := exp.Arguments

		if len(args) != len(params) {
			l.Error(&LintError{
				Severity: ERROR,
				Token:    exp.Function.GetMeta().Token,
				Message: fmt.Sprintf(
					"Function %s expects %d parameter(s) but got %d argument(s)",
					exp.Function.Value, len(params), len(args),
				),
			})
		} else {
			for i, arg := range args {
				param := params[i]
				expectedType := types.ValueTypeMap[param.Type.Value]
				actualType := l.lint(arg, ctx)

				if expectedType != actualType {
					l.Error(&LintError{
						Severity: ERROR,
						Token:    arg.GetMeta().Token,
						Message: fmt.Sprintf(
							"Parameter %s expects type %s but got %s",
							param.Name.Value, expectedType, actualType,
						),
					})
				}
			}
		}

		sub.IsUsed = true
		return types.ValueTypeMap[sub.Decl.ReturnType.Value]
	}

	fn, err := ctx.GetFunction(exp.Function.Value)
	if err != nil {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    exp.Function.GetMeta().Token,
			Message:  err.Error(),
		})
		return types.NeverType
	}

	return l.lintFunctionArguments(fn, functionMeta{
		name:      exp.Function.String(),
		token:     exp.Function.GetMeta().Token,
		arguments: exp.Arguments,
		meta:      exp.Meta,
	}, ctx)
}
