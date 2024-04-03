package formatter

import (
	"bytes"
	"fmt"

	"github.com/ysugimoto/falco/ast"
)

// Format expressions.
// Note that expressions may be chunked by limited line characters.
func (f *Formatter) formatExpression(expr ast.Expression) *ChunkBuffer {
	buf := f.chunkBuffer()

	// leading comment
	if v := f.formatComment(expr.GetMeta().Leading, "", 0); v != "" {
		buf.WriteComment(v)
	}

	switch t := expr.(type) {
	// Primitive types return string
	case *ast.Ident:
		buf.WriteString(f.formatIdent(t))
	case *ast.IP:
		buf.WriteString(f.formatIP(t))
	case *ast.Boolean:
		buf.WriteString(f.formatBoolean(t))
	case *ast.Integer:
		buf.WriteString(f.formatInteger(t))
	case *ast.String:
		buf.WriteString(f.formatString(t))
	case *ast.Float:
		buf.WriteString(f.formatFloat(t))
	case *ast.RTime:
		buf.WriteString(f.formatRTime(t))
	case *ast.FunctionCallExpression:
		buf.WriteString(f.formatFunctionCallExpression(t))
	case *ast.IfExpression:
		buf.WriteString(f.formatIfExpression(t))

	// Combinated expressions return *ChunkBuffer to merge
	case *ast.PrefixExpression:
		buf.Merge(f.formatPrefixExpression(t))
	case *ast.GroupedExpression:
		buf.Merge(f.formatGroupedExpression(t))
	case *ast.InfixExpression:
		buf.Merge(f.formatInfixExpression(t))
	}

	// trailing comment
	if v := f.formatComment(expr.GetMeta().Trailing, "", 0); v != "" {
		buf.WriteComment(v)
	}

	return buf
}

// Primitive Expressions

func (f *Formatter) formatIdent(expr *ast.Ident) string {
	return expr.Value
}

func (f *Formatter) formatIP(expr *ast.IP) string {
	return expr.Value
}

func (f *Formatter) formatBoolean(expr *ast.Boolean) string {
	return fmt.Sprintf("%t", expr.Value)
}

func (f *Formatter) formatInteger(expr *ast.Integer) string {
	return fmt.Sprint(expr.Value)
}

func (f *Formatter) formatFloat(expr *ast.Float) string {
	return fmt.Sprint(expr.Value)
}

func (f *Formatter) formatString(expr *ast.String) string {
	if expr.Token.Offset == 4 {
		// offset=4 means bracket string like {"..."}
		return fmt.Sprintf(`{"%s"}`, expr.Value)
	}
	// Otherwise, double-quoted string
	return fmt.Sprintf(`"%s"`, expr.Value)
}

func (f *Formatter) formatRTime(expr *ast.RTime) string {
	return expr.Value
}

// Combinated expressions

// Format prefix expression like "!foo"
func (f *Formatter) formatPrefixExpression(expr *ast.PrefixExpression) *ChunkBuffer {
	buf := f.chunkBuffer()

	buf.WriteString(expr.Operator)
	buf.Merge(f.formatExpression(expr.Right))

	return buf
}

func (f *Formatter) formatInfixExpression(expr *ast.InfixExpression) *ChunkBuffer {
	buf := f.chunkBuffer()

	operator := expr.Operator
	if expr.Operator == "+" { // concatenation
		if !f.conf.ExplicitStringConat {
			operator = ""
		}
	}

	buf.Merge(f.formatExpression(expr.Left))
	if operator != "" {
		buf.WriteOperator(operator)
	}
	buf.Merge(f.formatExpression(expr.Right))

	return buf
}

// Format prefix expression like `if(req.http.Foo, "foo", "bar")`
func (f *Formatter) formatIfExpression(expr *ast.IfExpression) string {
	var buf bytes.Buffer

	buf.WriteString("if(")
	buf.WriteString(f.formatExpression(expr.Condition).String())
	buf.WriteString(", ")
	buf.WriteString(f.formatExpression(expr.Consequence).String())
	buf.WriteString(", ")
	buf.WriteString(f.formatExpression(expr.Alternative).String())
	buf.WriteString(")")

	return buf.String()
}

// Format parenthesis surrounded expression like `(req.http.Foo)`
func (f *Formatter) formatGroupedExpression(expr *ast.GroupedExpression) *ChunkBuffer {
	buf := f.chunkBuffer()

	buf.WriteOperator("(")
	buf.Merge(f.formatExpression(expr.Right))
	buf.WriteOperator(")")

	return buf
}

// Format function call expression like `regsuball(req.http.Foo, ".*", "$1")`
func (f *Formatter) formatFunctionCallExpression(expr *ast.FunctionCallExpression) string {
	var buf bytes.Buffer

	buf.WriteString(expr.Function.Value + "(")
	for i, arg := range expr.Arguments {
		buf.WriteString(f.formatExpression(arg).String())
		if i != len(expr.Arguments)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(")")

	return buf.String()
}
