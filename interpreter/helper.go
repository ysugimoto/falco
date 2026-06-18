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

// isHeaderFieldIdent reports whether the supplied identifier refers to an http
// header field (i.e. is of the form <object>.http.<header>:<field>).
func isHeaderFieldIdent(ident *ast.Ident) bool {
	name, _, found := strings.Cut(ident.Value, ":")
	return found && strings.Contains(name, ".http.")
}

// isRequestHeaderIdent reports whether the identifier refers to a request header
// (req.http.*). Each write to one is assembled in the request workspace.
func isRequestHeaderIdent(ident *ast.Ident) bool {
	return strings.HasPrefix(ident.Value, "req.http.")
}

// requestHeaderName returns the bare header name Fastly charges the workspace
// for (e.g. `X-Foo`), not the VCL identifier.
func requestHeaderName(ident *ast.Ident) string {
	name := strings.TrimPrefix(ident.Value, "req.http.")
	if before, _, found := strings.Cut(name, ":"); found {
		name = before
	}
	return name
}

// roundUpToPointer rounds a workspace allocation up to the next 8 byte boundary,
// as Fastly does for every header allocation.
func roundUpToPointer(n int) int {
	const align = 8
	return (n + align - 1) &^ (align - 1)
}

// Validate type string is Fastly supported value type
func isValidFastlyTypeString(t string) bool {
	switch t {
	case "INTEGER", "FLOAT", "BOOL", "ACL", "BACKEND", "IP", "STRING", "RTIME", "TIME":
		return true
	}
	return false
}
