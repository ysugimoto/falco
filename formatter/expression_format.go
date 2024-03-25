package formatter

import (
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
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += expr.Value
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatIP(expr *ast.IP) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += expr.Value
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatBoolean(expr *ast.Boolean) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	str := fmt.Sprintf("%t", expr.Value)
	if f.conf.BoolUpperCase {
		ret += strings.ToUpper(str)
	} else {
		ret += strings.ToLower(str)
	}
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatInteger(expr *ast.Integer) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += fmt.Sprint(expr.Value)
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatFloat(expr *ast.Float) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += fmt.Sprint(expr.Value)
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatString(expr *ast.String) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	if expr.Token.Offset == 4 {
		// offset=4 means bracket-ed string line {"..."}
		ret += fmt.Sprintf(`{"%s"}`, expr.Value)
	} else {
		// Otherwise, double quoted string
		ret += fmt.Sprintf(`"%s"`, expr.Value)
	}
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatRTime(expr *ast.RTime) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += expr.Value
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatPrefixExpression(expr *ast.PrefixExpression) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += expr.Operator
	ret += f.formatExpression(expr.Right)
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatInfixExpression(expr *ast.InfixExpression) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += f.formatExpression(expr.Left)
	if expr.Operator == "+" { // concatenation
		if f.conf.ExplicitStringConat {
			ret += " + "
		} else {
			ret += " "
		}
	} else {
		ret += " " + expr.Operator + " "
	}
	ret += f.formatExpression(expr.Right)
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatIfExpression(expr *ast.IfExpression) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += "if("
	ret += f.formatExpression(expr.Condition)
	ret += ", "
	ret += f.formatExpression(expr.Consequence)
	ret += ", "
	ret += f.formatExpression(expr.Alternative)
	ret += ")"
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatGroupedExpression(expr *ast.GroupedExpression) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += "("
	ret += f.formatExpression(expr.Right)
	ret += ")"
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}

func (f *Formatter) formatFunctionCallExpression(expr *ast.FunctionCallExpression) string {
	var ret string
	if v := f.formatComment(expr.Leading, "", 0); v != "" {
		ret += v + " "
	}
	ret += expr.Function.Value + "("
	for i, arg := range expr.Arguments {
		ret += f.formatExpression(arg)
		if i != len(expr.Arguments)-1 {
			ret += ", "
		}
	}
	ret += ")"
	if v := f.formatComment(expr.Trailing, "", 0); v != "" {
		ret += " " + v
	}
	return ret
}
