package interpreter

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/value"
)

func findProcessMark(comments ast.Comments) (string, bool) {
	for i := range comments {
		l := strings.TrimLeft(comments[i].Value, " */#")
		if strings.HasPrefix(l, "@process") {
			return strings.TrimSpace(strings.TrimPrefix(l, "@process")), true
		}
	}

	return "", false
}

type series struct {
	Operator   string
	Expression ast.Expression
}

func isValidStatementExpression(left value.Type, exp ast.Expression) error {
	switch t := exp.(type) {
	case *ast.PrefixExpression:
		if t.Operator == "!" {
			return fmt.Errorf("could not specify bang operator in first expression")
		}
	case *ast.InfixExpression:
		if t.Operator != "+" {
			return fmt.Errorf("could not specify %s operator in statement", t.Operator)
		}
	case *ast.GroupedExpression:
		if left != value.BooleanType {
			return fmt.Errorf("could not specify grouped expression excepting boolean statement")
		}
	}
	return nil
}
