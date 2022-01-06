package linter

import (
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/types"
)

// See expression type comparison table:
// https://docs.google.com/spreadsheets/d/16xRPugw9ubKA1nXHIc5ysVZKokLLhysI-jAu3qbOFJ8/edit#gid=0

// Lint assignment operator of "="
func (l *Linter) lintAssignOperator(op *ast.Operator, name string, left, right types.Type, isLiteral bool) {
	switch left {
	case types.IntegerType:
		switch right {
		// allows both variable and literal
		case types.IntegerType:
			return
		// allows variable only, disallow literal
		case types.FloatType, types.RTimeType, types.TimeType:
			if isLiteral {
				l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
			}
		// disallow
		default:
			l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
		}
	case types.FloatType:
		switch right {
		// allows both variable and literal
		case types.IntegerType, types.FloatType:
			return
		// allows variable only, disallow literal
		case types.RTimeType, types.TimeType:
			if isLiteral {
				l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
			}
		// disallow
		default:
			l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
		}
	case types.StringType:
		switch right {
		// allows both variable and literal
		case types.StringType, types.BoolType:
			return
		// allows variable only, disallow literal
		case types.IntegerType, types.FloatType, types.RTimeType, types.TimeType, types.IPType:
			if isLiteral {
				l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
			}
		// disallow
		default:
			l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
		}
	case types.RTimeType, types.TimeType:
		switch right {
		// allows both variable and literal
		case types.RTimeType, types.TimeType:
			return
		// allows variable only, disallow literal
		case types.IntegerType, types.FloatType:
			if isLiteral {
				l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
			}
		// disallow
		default:
			l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
		}
	case types.IPType:
		switch right {
		// allows both variable and literal
		case types.StringType, types.IPType:
			return
		// disallow
		default:
			l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
		}
	default: // types.BackendType or types.BoolType
		if left != right {
			l.Error(InvalidType(op.Meta, name, left, right).Match(OPERATOR_ASSIGNMENT))
		}
	}
}

// Lint addition and subtraction operator of "+=" and "-="
func (l *Linter) lintAddSubOperator(op *ast.Operator, left, right types.Type, isLiteral bool) {
	switch left {
	case types.IntegerType:
		switch right {
		// allows both variable and literal
		case types.IntegerType:
			return
		// allows variable only, disallow literal
		case types.FloatType, types.RTimeType, types.TimeType:
			if isLiteral {
				l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
			}
		// disallow
		default:
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
		}
	case types.FloatType:
		switch right {
		// allows both variable and literal
		case types.IntegerType, types.FloatType:
			return
		// allows variable only, disallow literal
		case types.RTimeType, types.TimeType:
			if isLiteral {
				l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
			}
		// disallow
		default:
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
		}
	case types.RTimeType:
		switch right {
		// allows both variable and literal
		case types.RTimeType:
			return
		// allows variable only, disallow literal
		case types.IntegerType, types.FloatType, types.TimeType:
			if isLiteral {
				l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
			}
		// disallow
		default:
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
		}
	case types.TimeType:
		switch right {
		// allows both variable and literal
		case types.RTimeType:
			return
		// allows variable only, disallow literal
		case types.IntegerType, types.FloatType:
			if isLiteral {
				l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
			}
		// disallow
		default:
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
		}
	default:
		// disallow other types
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_CONDITIONAL))
	}
}

// Lint arithmetic operator excepts addition and subtraction. Lint "*=", "/=" and "%=" operator
func (l *Linter) lintArithmeticOpereator(op *ast.Operator, left, right types.Type, isLiteral bool) {
	switch left {
	case types.IntegerType:
		switch right {
		// allows both variable and literal
		case types.IntegerType:
			return
		// allows variable only, disallow literal
		case types.FloatType:
			if isLiteral {
				l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
			}
		// disallow
		default:
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
		}
	case types.FloatType, types.RTimeType:
		switch right {
		// allows both variable and literal
		case types.IntegerType, types.FloatType:
			return
		// disallow
		default:
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_ASSIGNMENT))
	}
}

// Lint bitwise related operators "|=", "&=", "^=", "<<=", ">>=", "rol=" and "ror=".
func (l *Linter) lintBitwiseOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.IntegerType:
		if right != types.IntegerType {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_CONDITIONAL))
	}
}

// Lint logical operators "||=" and "&&=".
func (l *Linter) lintLogicalOperator(op *ast.Operator, left, right types.Type) {
	switch left {
	case types.BoolType:
		if right != types.BoolType {
			l.Error(InvalidTypeOperator(op.Meta, op.Operator, left, right).Match(OPERATOR_CONDITIONAL))
		}
	default:
		l.Error(InvalidOperator(op.Meta, op.Operator, left).Match(OPERATOR_CONDITIONAL))
	}
}
