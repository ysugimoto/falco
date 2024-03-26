package formatter

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
)

func (f *Formatter) formatExpression(expr ast.Expression) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return f.formatIdent(t)
	case *ast.IP:
		return f.formatIP(t)
	case *ast.Boolean:
		return f.formatBoolean(t)
	case *ast.Integer:
		return f.formatInteger(t)
	case *ast.String:
		return f.formatString(t)
	case *ast.Float:
		return f.formatFloat(t)
	case *ast.RTime:
		return f.formatRTime(t)
	case *ast.PrefixExpression:
		return f.formatPrefixExpression(t)
	case *ast.GroupedExpression:
		return f.formatGroupedExpression(t)
	case *ast.InfixExpression:
		return f.formatInfixExpression(t)
	case *ast.IfExpression:
		return f.formatIfExpression(t)
	case *ast.FunctionCallExpression:
		return f.formatFunctionCallExpression(t)
	default:
		return ""
	}
}

func (f *Formatter) formatIdent(expr *ast.Ident) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(expr.Value)
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}
	return buf.String()
}

func (f *Formatter) formatIP(expr *ast.IP) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(expr.Value)
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}
	return buf.String()
}

func (f *Formatter) formatBoolean(expr *ast.Boolean) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	str := fmt.Sprintf("%t", expr.Value)
	if f.conf.BoolUpperCase {
		buf.WriteString(strings.ToUpper(str))
	} else {
		buf.WriteString(strings.ToLower(str))
	}
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}

	return buf.String()
}

func (f *Formatter) formatInteger(expr *ast.Integer) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(fmt.Sprint(expr.Value))
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}

	return buf.String()
}

func (f *Formatter) formatFloat(expr *ast.Float) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(fmt.Sprint(expr.Value))
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}

	return buf.String()
}

func (f *Formatter) formatString(expr *ast.String) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	if expr.Token.Offset == 4 {
		// offset=4 means bracket string like {"..."}
		buf.WriteString(fmt.Sprintf(`{"%s"}`, expr.Value))
	} else {
		// Otherwise, double quoted string
		buf.WriteString(fmt.Sprintf(`"%s"`, expr.Value))
	}
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}

	return buf.String()
}

func (f *Formatter) formatRTime(expr *ast.RTime) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(expr.Value)
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}

	return buf.String()
}

func (f *Formatter) formatPrefixExpression(expr *ast.PrefixExpression) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(expr.Operator)
	buf.WriteString(f.formatExpression(expr.Right))
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}

	return buf.String()
}

func (f *Formatter) formatInfixExpression(expr *ast.InfixExpression) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(f.formatExpression(expr.Left))

	if expr.Operator == "+" { // concatenation
		if f.conf.ExplicitStringConat {
			buf.WriteString(" + ")
		} else {
			buf.WriteString(" ")
		}
	} else {
		buf.WriteString(" " + expr.Operator + " ")
	}
	buf.WriteString(f.formatExpression(expr.Right))
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}

	return buf.String()
}

func (f *Formatter) formatIfExpression(expr *ast.IfExpression) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString("if(")
	buf.WriteString(f.formatExpression(expr.Condition))
	buf.WriteString(", ")
	buf.WriteString(f.formatExpression(expr.Consequence))
	buf.WriteString(", ")
	buf.WriteString(f.formatExpression(expr.Alternative))
	buf.WriteString(")")
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}

	return buf.String()
}

func (f *Formatter) formatGroupedExpression(expr *ast.GroupedExpression) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString("(" + f.formatExpression(expr.Right) + ")")
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(" " + v)
	}

	return buf.String()
}

func (f *Formatter) formatFunctionCallExpression(expr *ast.FunctionCallExpression) string {
	var buf bytes.Buffer

	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(expr.Function.Value + "(")
	for i, arg := range expr.Arguments {
		buf.WriteString(f.formatExpression(arg))
		if i != len(expr.Arguments)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(")")
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		buf.WriteString(v + " ")
	}

	return buf.String()
}
