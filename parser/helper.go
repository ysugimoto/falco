package parser

import (
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

var assignmentOperators = map[token.TokenType]struct{}{
	token.ASSIGN:         {},
	token.ADDITION:       {},
	token.SUBTRACTION:    {},
	token.MULTIPLICATION: {},
	token.DIVISION:       {},
	token.REMAINDER:      {},
	token.BITWISE_AND:    {},
	token.BITWISE_OR:     {},
	token.BITWISE_XOR:    {},
	token.LEFT_SHIFT:     {},
	token.RIGHT_SHIFT:    {},
	token.LEFT_ROTATE:    {},
	token.RIGHT_ROTATE:   {},
	token.LOGICAL_AND:    {},
	token.LOGICAL_OR:     {},
}

var assignmentOperatorLiterals = []string{
	"=",
	"+=",
	"-=",
	"*=",
	"/=",
	"%=",
	"|=",
	"&=",
	"^=",
	"<<=",
	">>=",
	"rol=",
	"ror=",
	"&&=",
	"||=",
}

func isAssignmentOperator(t token.Token) bool {
	if _, ok := assignmentOperators[t.Type]; ok {
		return true
	}
	return false
}

// Comment control helper
func SwapLeadingTrailing(from, to *ast.Meta) {
	to.Trailing = append(to.Trailing, from.Leading...)
	from.Leading = ast.Comments{}
}

func SwapLeadingInfix(from, to *ast.Meta) {
	to.Infix = append(to.Infix, from.Leading...)
	from.Leading = ast.Comments{}
}

func clearComments(m *ast.Meta) *ast.Meta {
	mm := *m
	mm.Leading = ast.Comments{}
	mm.Trailing = ast.Comments{}
	return &mm
}

func isGotoDestination(t token.Token) bool {
	components := strings.Split(t.Literal, ":")

	return len(components) == 2
}
