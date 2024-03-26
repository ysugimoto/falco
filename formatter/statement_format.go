package formatter

import (
	"bytes"

	"github.com/ysugimoto/falco/ast"
)

func (f *Formatter) formatStatement(stmt ast.Statement) string {
	switch t := stmt.(type) {
	case *ast.BlockStatement:
		return f.formatBlockStatement(t)
	case *ast.ImportStatement:
		return f.formatImportStatement(t)
	case *ast.IncludeStatement:
		return f.formatIncludeStatement(t)
	case *ast.DeclareStatement:
		return f.formatDeclareStatement(t)
	case *ast.SetStatement:
		return f.formatSetStatement(t)
	case *ast.UnsetStatement:
		return f.formatUnsetStatement(t)
	case *ast.RemoveStatement:
		return f.formatRemoveStatement(t)
	case *ast.IfStatement:
		return f.formatIfStatement(t)
	case *ast.SwitchStatement:
		return f.formatSwitchStatement(t)
	case *ast.RestartStatement:
		return f.formatRestartStatement(t)
	case *ast.EsiStatement:
		return f.formatEsiStatement(t)
	case *ast.AddStatement:
		return f.formatAddStatement(t)
	case *ast.CallStatement:
		return f.formatCallStatement(t)
	case *ast.ErrorStatement:
		return f.formatErrorStatement(t)
	case *ast.LogStatement:
		return f.formatLogStatement(t)
	case *ast.ReturnStatement:
		return f.formatReturnStatement(t)
	case *ast.SyntheticStatement:
		return f.formatSyntheticStatement(t)
	case *ast.SyntheticBase64Statement:
		return f.formatSyntheticBase64Statement(t)
	case *ast.GotoStatement:
		return f.formatGotoStatement(t)
	case *ast.GotoDestinationStatement:
		return f.formatGotoDestinationStatement(t)
	case *ast.FunctionCallStatement:
		return f.formatFunctionCallStatement(t)
	}
	return ""
}

func (f *Formatter) formatImportStatement(stmt *ast.ImportStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString("import ")
	buf.WriteString(`"` + stmt.Name.Value + `"`)
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatIncludeStatement(stmt *ast.IncludeStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString("include ")
	buf.WriteString(f.formatString(stmt.Module))
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatBlockStatement(stmt *ast.BlockStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString("{\n")

	for i := range stmt.Statements {
		buf.WriteString(f.formatStatement(stmt.Statements[i]))
		buf.WriteString("\n")
	}
	if len(stmt.Infix) > 0 {
		buf.WriteString(f.formatComment(stmt.Infix, "\n", stmt.Meta.Nest))
	}
	buf.WriteString("}")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatDeclareStatement(stmt *ast.DeclareStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString("declare local " + stmt.Name.Value)
	buf.WriteString(" " + stmt.ValueType.Value)
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatSetStatement(stmt *ast.SetStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString("set " + stmt.Ident.Value)
	buf.WriteString(" " + stmt.Operator.Operator + " ")
	buf.WriteString(f.formatExpression(stmt.Value))
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatUnsetStatement(stmt *ast.UnsetStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("unset " + stmt.Ident.Value)
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatRemoveStatement(stmt *ast.RemoveStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("remove " + stmt.Ident.Value)
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatIfStatement(stmt *ast.IfStatement) string {
}

func (f *Formatter) formatSwitchStatement(stmt *ast.SwitchStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("switch (" + f.formatExpression(stmt.Control) + ") {\n")
	for _, c := range stmt.Cases {
		buf.WriteString(f.formatComment(c.Leading, "\n", c.Meta.Nest))
		buf.WriteString(f.indent(c.Meta.Nest))
		if c.Test != nil {
			buf.WriteString("case ")
			if c.Test.Operator == "~" {
				buf.WriteString("~ ")
			}
			buf.WriteString(f.formatExpression(c.Test.Right))
			buf.WriteString(":\n")
		} else {
			buf.WriteString("default:\n")
		}
		for _, s := range c.Statements {
			if _, ok := s.(*ast.BreakStatement); ok {
				buf.WriteString(f.indent(c.Meta.Nest + 1))
				buf.WriteString("break;")
			} else {
				buf.WriteString(f.formatStatement(s))
			}
			buf.WriteString("\n")
		}
		if c.Fallthrough {
			buf.WriteString(f.indent(c.Meta.Nest + 1))
			buf.WriteString("fallthrough;\n")
		}
	}
	if len(stmt.Infix) > 0 {
		buf.WriteString(f.formatComment(stmt.Infix, "\n", stmt.Meta.Nest))
	}
	buf.WriteString("}")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatRestartStatement(stmt *ast.RestartStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("restart;")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatEsiStatement(stmt *ast.EsiStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("esi;")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatAddStatement(stmt *ast.AddStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("add " + stmt.Ident.Value)
	buf.WriteString(" " + stmt.Operator.Operator + " ")
	buf.WriteString(f.formatExpression(stmt.Value))
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatCallStatement(stmt *ast.CallStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("call " + stmt.Subroutine.Value)
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatErrorStatement(stmt *ast.ErrorStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("error " + f.formatExpression(stmt.Code))
	if stmt.Argument != nil {
		buf.WriteString(" " + f.formatExpression(stmt.Argument))
	}
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatLogStatement(stmt *ast.LogStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("log " + f.formatExpression(stmt.Value))
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatReturnStatement(stmt *ast.ReturnStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("return")
	if stmt.HasParenthesis {
		buf.WriteString(" (")
	}
	if stmt.ReturnExpression != nil {
		buf.WriteString(f.formatExpression(*stmt.ReturnExpression))
	}
	if stmt.HasParenthesis {
		buf.WriteString(")")
	}
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatSyntheticStatement(stmt *ast.SyntheticStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("synthetic " + f.formatExpression(stmt.Value))
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatSyntheticBase64Statement(stmt *ast.SyntheticBase64Statement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("synthetic.base64 " + f.formatExpression(stmt.Value))
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatGotoStatement(stmt *ast.GotoStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("goto " + stmt.Destination.Value)
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}

func (f *Formatter) formatGotoDestinationStatement(stmt *ast.GotoDestinationStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString(stmt.Name.Value)
	buf.WriteString(";")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}
func (f *Formatter) formatFunctionCallStatement(stmt *ast.FunctionCallStatement) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(stmt.Leading, "\n", stmt.Meta.Nest))
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString(stmt.Function.Value + "(")
	for i, a := range stmt.Arguments {
		buf.WriteString(f.formatExpression(a))
		if i != len(stmt.Arguments)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(");")
	if len(stmt.Trailing) > 0 {
		buf.WriteString("  ")
		buf.WriteString(f.formatComment(stmt.Trailing, "", 0))
	}

	return buf.String()
}
