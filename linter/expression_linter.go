package linter

import (
	"fmt"
	"net"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/context"
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

func (l *Linter) lintInfixExpression(exp *ast.InfixExpression, ctx *context.Context) types.Type {
	// Type comparison
	left := l.lint(exp.Left, ctx)
	if left == types.NeverType {
		return left
	}
	right := l.lint(exp.Right, ctx)
	if right == types.NeverType {
		return right
	}

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
		// Regex operator could compare only STRING,  IP or ACL type
		if !expectType(left, types.StringType, types.IPType) {
			l.Error(InvalidTypeExpression(exp.GetMeta(), left, types.StringType, types.IPType, types.AclType).Match(OPERATOR_CONDITIONAL))
		} else if !expectType(right, types.StringType, types.AclType) {
			l.Error(InvalidTypeExpression(exp.GetMeta(), right, types.StringType).Match(OPERATOR_CONDITIONAL))
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
	case "+":
		// Plus operator behaves string concatenation.
		// VCL accepts other types with implicit type conversion as following:
		// IDENT   -> point value
		// STRING  -> raw string
		// INTEGER -> stringify
		// FLOAT   -> stringify
		// IP      -> stringify
		// TIME    -> stringify (GMT string)
		// RTIME   -> stringify (GMT string)
		// BOOL    -> 0 (false) or 1 (true)
		switch left {
		case types.AclType, types.BackendType:
			err := &LintError{
				Severity: ERROR,
				Token:    exp.GetMeta().Token,
				Message:  "ACL or BACKEND type cannot use in string concatenation",
			}
			l.Error(err.Match(OPERATOR_CONDITIONAL))
		case types.StringType:
			break
		default:
			l.Error(ImplicitTypeConversion(exp.GetMeta(), left, types.StringType))
		}

		switch right {
		case types.AclType, types.BackendType:
			l.Error(&LintError{
				Severity: ERROR,
				Token:    exp.GetMeta().Token,
				Message:  "ACL or BACKEND type cannot use in string concatenation",
			})
		case types.StringType:
			break
		default:
			l.Error(ImplicitTypeConversion(exp.GetMeta(), right, types.StringType))
		}
		return types.StringType
	case "&&", "||":
		// AND / OR operator compares left and right with truthy or falsy
		return types.BoolType
	default:
		return types.NeverType
	}
}

func (l *Linter) lintIfExpression(exp *ast.IfExpression, ctx *context.Context) types.Type {
	l.lintIfCondition(exp.Condition, ctx)
	if err := pushRegexGroupVars(exp.Condition, ctx); err != nil {
		err := &LintError{
			Severity: INFO,
			Token:    exp.Condition.GetMeta().Token,
			Message:  err.Error(),
		}
		l.Error(err.Match(REGEX_MATCHED_VALUE_MAY_OVERRIDE))
	}

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
