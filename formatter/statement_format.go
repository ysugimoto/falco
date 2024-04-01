package formatter

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
)

func (f *Formatter) formatStatement(stmt ast.Statement) *Line {
	if block, ok := stmt.(*ast.BlockStatement); ok {
		return &Line{
			// need subtract 1 because LEFT_BRACE is unnested
			Leading:  f.formatComment(block.Leading, "\n", block.Nest-1),
			Trailing: f.trailing(block.Trailing),
			Buffer:   f.indent(block.Nest-1) + f.formatBlockStatement(block),
		}
	}

	line := &Line{
		Leading: f.formatComment(stmt.GetMeta().Leading, "\n", stmt.GetMeta().Nest),
		Buffer:  f.indent(stmt.GetMeta().Nest),
	}

	trailingNode := stmt
	switch t := stmt.(type) {
	case *ast.ImportStatement:
		line.Buffer += f.formatImportStatement(t)
	case *ast.IncludeStatement:
		line.Buffer += f.formatIncludeStatement(t)
	case *ast.DeclareStatement:
		line.Buffer += f.formatDeclareStatement(t)
	case *ast.SetStatement:
		line.Buffer += f.formatSetStatement(t)
	case *ast.UnsetStatement:
		line.Buffer += f.formatUnsetStatement(t)
	case *ast.RemoveStatement:
		line.Buffer += f.formatRemoveStatement(t)
	case *ast.SwitchStatement:
		line.Buffer += f.formatSwitchStatement(t)
	case *ast.RestartStatement:
		line.Buffer += f.formatRestartStatement()
	case *ast.EsiStatement:
		line.Buffer += f.formatEsiStatement()
	case *ast.AddStatement:
		line.Buffer += f.formatAddStatement(t)
	case *ast.CallStatement:
		line.Buffer += f.formatCallStatement(t)
	case *ast.ErrorStatement:
		line.Buffer += f.formatErrorStatement(t)
	case *ast.LogStatement:
		line.Buffer += f.formatLogStatement(t)
	case *ast.ReturnStatement:
		line.Buffer += f.formatReturnStatement(t)
	case *ast.SyntheticStatement:
		line.Buffer += f.formatSyntheticStatement(t)
	case *ast.SyntheticBase64Statement:
		line.Buffer += f.formatSyntheticBase64Statement(t)
	case *ast.GotoStatement:
		line.Buffer += f.formatGotoStatement(t)
	case *ast.GotoDestinationStatement:
		line.Buffer += f.formatGotoDestinationStatement(t)
	case *ast.FunctionCallStatement:
		line.Buffer += f.formatFunctionCallStatement(t)

	// On if statement, trailing comment node depends on its declarations
	case *ast.IfStatement:
		line.Buffer += f.formatIfStatement(t)
		switch {
		case t.Alternative != nil:
			// When "else" statament exists, trailing comment will be on it
			trailingNode = t.Alternative
		case len(t.Another) > 0:
			// When one of "else if" statament exists, trailing comment will be on it
			trailingNode = t.Another[len(t.Another)-1]
		default:
			// Otherwise, trailing comment will be on consequence
			trailingNode = t.Consequence
		}
	}
	line.Trailing = f.trailing(trailingNode.GetMeta().Trailing)

	return line
}

func (f *Formatter) formatImportStatement(stmt *ast.ImportStatement) string {
	var buf bytes.Buffer

	buf.WriteString("import ")
	buf.WriteString(stmt.Name.Value)
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatIncludeStatement(stmt *ast.IncludeStatement) string {
	var buf bytes.Buffer

	buf.WriteString("include ")
	buf.WriteString(f.formatString(stmt.Module))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatBlockStatement(stmt *ast.BlockStatement) string {
	group := &GroupedLines{}
	lines := Lines{}

	for _, s := range stmt.Statements {
		if s.GetMeta().PreviousEmptyLines > 0 {
			group.Lines = append(group.Lines, lines)
			lines = Lines{}
		}
		lines = append(lines, f.formatStatement(s))
	}

	if len(lines) > 0 {
		group.Lines = append(group.Lines, lines)
	}
	if f.conf.AlignTrailingComment {
		group.Align()
	}

	var buf bytes.Buffer
	buf.WriteString("{\n")
	buf.WriteString(group.String())
	if len(stmt.Infix) > 0 {
		buf.WriteString(f.formatComment(stmt.Infix, "\n", stmt.Meta.Nest))
	}
	// need subtract 1 because RIGHT_BRACE is unnested
	buf.WriteString(f.indent(stmt.Meta.Nest - 1))
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatDeclareStatement(stmt *ast.DeclareStatement) string {
	var buf bytes.Buffer

	buf.WriteString("declare local " + stmt.Name.Value)
	buf.WriteString(" " + stmt.ValueType.Value)
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatSetStatement(stmt *ast.SetStatement) string {
	var buf bytes.Buffer

	buf.WriteString("set " + stmt.Ident.Value)
	buf.WriteString(" " + stmt.Operator.Operator + " ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatUnsetStatement(stmt *ast.UnsetStatement) string {
	var buf bytes.Buffer

	buf.WriteString("unset " + stmt.Ident.Value)
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatRemoveStatement(stmt *ast.RemoveStatement) string {
	var buf bytes.Buffer

	buf.WriteString("remove " + stmt.Ident.Value)
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatIfStatement(stmt *ast.IfStatement) string {
	var buf bytes.Buffer

	buf.WriteString(stmt.Keyword + " (")

	// Condition expression chunk should be printed with multi-line
	offset := buf.Len()
	chunk := f.formatExpression(stmt.Condition).ChunkedString(stmt.Nest, offset)
	if strings.Contains(chunk, "\n") {
		buf.WriteString(
			fmt.Sprintf(
				"\n%s%s%s\n",
				f.indent(stmt.Nest),
				strings.Repeat(" ", offset),
				chunk,
			),
		)
		buf.WriteString(f.indent(stmt.Nest) + ") ")
	} else {
		buf.WriteString(chunk + ") ")
	}

	buf.WriteString(f.formatBlockStatement(stmt.Consequence))
	for _, a := range stmt.Another {
		// If leading comments exists, keyword should be placed with line-feed
		if len(a.Leading) > 0 {
			buf.WriteString("\n")
			buf.WriteString(f.formatComment(a.Leading, "\n", a.Nest))
			buf.WriteString(f.indent(a.Nest))
		} else {
			// Otherwise, write one whitespace characeter
			buf.WriteString(" ")
		}

		keyword := a.Keyword
		if f.conf.ElseIf {
			keyword = "else if"
		}
		chunk := f.formatExpression(a.Condition).ChunkedString(a.Nest, len(keyword)+2)
		buf.WriteString(keyword + " (")
		if strings.Contains(chunk, "\n") {
			buf.WriteString("\n" + chunk + "\n")
		} else {
			buf.WriteString(chunk)
		}
		buf.WriteString(") ")
		buf.WriteString(f.formatBlockStatement(a.Consequence))
	}
	if stmt.Alternative != nil {
		if len(stmt.Alternative.Leading) > 0 {
			buf.WriteString("\n")
			buf.WriteString(f.formatComment(stmt.Alternative.Leading, "\n", stmt.Alternative.Nest))
			buf.WriteString(f.indent(stmt.Alternative.Nest))
		} else {
			buf.WriteString(" ")
		}
		buf.WriteString("else ")
		buf.WriteString(f.formatBlockStatement(stmt.Alternative))
	}

	return buf.String()
}

func (f *Formatter) formatSwitchStatement(stmt *ast.SwitchStatement) string {
	var buf bytes.Buffer

	buf.WriteString("switch (" + f.formatExpression(stmt.Control).String() + ") {\n")
	for _, c := range stmt.Cases {
		buf.WriteString(f.formatComment(c.Leading, "\n", c.Meta.Nest))
		buf.WriteString(f.indent(c.Meta.Nest))
		if c.Test != nil {
			buf.WriteString("case ")
			if c.Test.Operator == "~" {
				buf.WriteString("~ ")
			}
			buf.WriteString(f.formatExpression(c.Test.Right).String())
			buf.WriteString(":\n")
		} else {
			buf.WriteString("default:\n")
		}
		buf.WriteString(f.formatCaseSectionStatements(c))
		buf.WriteString("\n")
	}
	if len(stmt.Infix) > 0 {
		buf.WriteString(f.formatComment(stmt.Infix, "\n", stmt.Meta.Nest))
	}
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatCaseSectionStatements(cs *ast.CaseStatement) string {
	group := &GroupedLines{}
	lines := Lines{}

	for _, stmt := range cs.Statements {
		if stmt.GetMeta().PreviousEmptyLines > 0 {
			group.Lines = append(group.Lines, lines)
			lines = Lines{}
		}
		line := &Line{
			Leading:  f.formatComment(stmt.GetMeta().Leading, "\n", stmt.GetMeta().Nest),
			Trailing: f.formatComment(stmt.GetMeta().Trailing, "\n", stmt.GetMeta().Nest),
		}
		if _, ok := stmt.(*ast.BreakStatement); ok {
			line.Buffer = f.indent(stmt.GetMeta().Nest+1) + "break;"
		} else {
			line.Buffer = f.formatStatement(stmt).String()
		}
		lines = append(lines, line)
	}

	if len(lines) > 0 {
		group.Lines = append(group.Lines, lines)
	}

	if f.conf.AlignTrailingComment {
		group.Align()
	}

	var buf bytes.Buffer
	buf.WriteString(group.String())
	if cs.Fallthrough {
		buf.WriteString(f.indent(cs.Meta.Nest + 1))
		buf.WriteString("fallthrough;")
	}

	return buf.String()
}

func (f *Formatter) formatRestartStatement() string {
	var buf bytes.Buffer

	buf.WriteString("restart;")

	return buf.String()
}

func (f *Formatter) formatEsiStatement() string {
	var buf bytes.Buffer

	buf.WriteString("esi;")

	return buf.String()
}

func (f *Formatter) formatAddStatement(stmt *ast.AddStatement) string {
	var buf bytes.Buffer

	buf.WriteString("add " + stmt.Ident.Value)
	buf.WriteString(" " + stmt.Operator.Operator + " ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatCallStatement(stmt *ast.CallStatement) string {
	var buf bytes.Buffer

	buf.WriteString("call " + stmt.Subroutine.Value)
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatErrorStatement(stmt *ast.ErrorStatement) string {
	var buf bytes.Buffer

	buf.WriteString("error " + f.formatExpression(stmt.Code).String())
	if stmt.Argument != nil {
		buf.WriteString(" " + f.formatExpression(stmt.Argument).String())
	}
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatLogStatement(stmt *ast.LogStatement) string {
	var buf bytes.Buffer

	buf.WriteString("log ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatReturnStatement(stmt *ast.ReturnStatement) string {
	var buf bytes.Buffer

	buf.WriteString("return")
	if stmt.ReturnExpression != nil {
		prefix := " "
		suffix := ""
		if f.conf.ReturnStatementParenthesis {
			prefix = " ("
			suffix = ")"
		}
		buf.WriteString(prefix)
		buf.WriteString(f.formatExpression(*stmt.ReturnExpression).String())
		buf.WriteString(suffix)
	}
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatSyntheticStatement(stmt *ast.SyntheticStatement) string {
	var buf bytes.Buffer

	buf.WriteString("synthetic ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatSyntheticBase64Statement(stmt *ast.SyntheticBase64Statement) string {
	var buf bytes.Buffer

	buf.WriteString("synthetic.base64 ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatGotoStatement(stmt *ast.GotoStatement) string {
	var buf bytes.Buffer

	buf.WriteString("goto " + stmt.Destination.Value)
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatGotoDestinationStatement(stmt *ast.GotoDestinationStatement) string {
	var buf bytes.Buffer

	buf.WriteString(stmt.Name.Value)

	return buf.String()
}

func (f *Formatter) formatFunctionCallStatement(stmt *ast.FunctionCallStatement) string {
	var buf bytes.Buffer

	buf.WriteString(stmt.Function.Value + "(")
	length := buf.Len()
	for i, a := range stmt.Arguments {
		buf.WriteString(f.formatExpression(a).ChunkedString(stmt.Nest, length))
		if i != len(stmt.Arguments)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(");")

	return buf.String()
}
