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
		if process, found := strings.CutPrefix(l, "@process"); found {
			return strings.TrimSpace(process), true
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

func isLocalVariableIdent(ident *ast.Ident) bool {
	return strings.HasPrefix(ident.Value, "var.")
}

// Validate type string is Fastly supported value type
func isValidFastlyTypeString(t string) bool {
	switch t {
	case "INTEGER", "FLOAT", "BOOL", "ACL", "BACKEND", "IP", "STRING", "RTIME", "TIME":
		return true
	}
	return false
}
