package formatter

import (
	"strings"

	"github.com/ysugimoto/falco/ast"
)

type conditionPart struct {
	expr ast.Expression
	op   string
	isOp bool
}

// collectCompoundConditionParts flattens top-level && and || into a linear list.
// Grouped expressions are treated as a single operand so nested formatting can be handled separately.
func collectCompoundConditionParts(expr ast.Expression, parts *[]conditionPart) bool {
	switch t := expr.(type) {
	case *ast.GroupedExpression:
		*parts = append(*parts, conditionPart{expr: expr})
		return false
	case *ast.InfixExpression:
		if t.Operator == "&&" || t.Operator == "||" {
			collectCompoundConditionParts(t.Left, parts)
			*parts = append(*parts, conditionPart{isOp: true, op: t.Operator})
			collectCompoundConditionParts(t.Right, parts)
			return true
		}
	}

	*parts = append(*parts, conditionPart{expr: expr})
	return false
}

// formatConditionLines returns formatted condition lines and whether it is multiline.
// The preserve flag indicates that existing indentation in the returned lines must be kept.
func (f *Formatter) formatConditionLines(expr ast.Expression) ([]string, bool, bool) {
	switch t := expr.(type) {
	case *ast.GroupedExpression:
		// If the grouped expression contains compound operators, format it as a nested block.
		var parts []conditionPart
		if f.conf.BreakCompoundConditions && collectCompoundConditionParts(t.Right, &parts) {
			innerLines, _, _ := f.formatConditionLines(t.Right)
			lines := make([]string, 0, len(innerLines)+2)
			lines = append(lines, "(")
			extraIndent := f.indent(1)
			for _, line := range innerLines {
				lines = append(lines, extraIndent+line)
			}
			lines = append(lines, ")")
			return lines, true, true
		}
		inner := strings.TrimSpace(f.formatExpression(t.Right).String())
		return []string{"(" + inner + ")"}, false, false
	case *ast.PrefixExpression:
		// Handle negation and other prefix operators containing compound conditions.
		rightLines, rightMultiline, rightPreserve := f.formatConditionLines(t.Right)
		if rightMultiline {
			rightLines[0] = t.Operator + rightLines[0]
			return rightLines, true, rightPreserve
		}
	case *ast.InfixExpression:
		// Only split compound boolean operators; other infix expressions stay inline.
		if t.Operator != "&&" && t.Operator != "||" {
			break
		}
		var parts []conditionPart
		if !collectCompoundConditionParts(expr, &parts) {
			break
		}

		var operands []ast.Expression
		var ops []string
		for _, part := range parts {
			if part.isOp {
				ops = append(ops, part.op)
				continue
			}
			operands = append(operands, part.expr)
		}

		if len(operands) == 0 || len(operands) != len(ops)+1 {
			break
		}

		lines := []string{}
		preserve := false
		for i, operand := range operands {
			opLines, _, opPreserve := f.formatConditionLines(operand)
			if len(opLines) == 0 {
				continue
			}
			if i < len(ops) {
				opLines[len(opLines)-1] = opLines[len(opLines)-1] + " " + ops[i]
			}
			lines = append(lines, opLines...)
			preserve = preserve || opPreserve
		}
		return lines, true, preserve
	}

	line := strings.TrimSpace(f.formatExpression(expr).String())
	return []string{line}, false, false
}

// formatConditionExpression returns a chunked condition string and flags indicating multiline/preserve.
func (f *Formatter) formatConditionExpression(expr ast.Expression, nest, offset int) (string, bool, bool) {
	if !f.conf.BreakCompoundConditions {
		chunk := f.formatExpression(expr).ChunkedString(nest, offset)
		return chunk, strings.Contains(chunk, "\n"), false
	}

	lines, multiline, preserve := f.formatConditionLines(expr)
	if !multiline {
		chunk := f.formatExpression(expr).ChunkedString(nest, offset)
		return chunk, strings.Contains(chunk, "\n"), false
	}

	return strings.Join(lines, "\n"), true, preserve
}
