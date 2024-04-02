package formatter

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/ysugimoto/falco/ast"
)

// Format acl declaration
func (f *Formatter) formatAclDeclaration(decl *ast.AclDeclaration) *Declaration {
	group := &GroupedLines{}
	lines := DelclarationPropertyLines{}

	for _, cidr := range decl.CIDRs {
		if cidr.GetMeta().PreviousEmptyLines > 0 {
			group.Lines = append(group.Lines, lines)
			lines = DelclarationPropertyLines{}
		}
		var buf bytes.Buffer
		buf.WriteString(f.indent(1))
		if cidr.Inverse != nil && cidr.Inverse.Value {
			buf.WriteString("!")
		}
		buf.WriteString(`"` + cidr.IP.String() + `"`)
		if cidr.Mask != nil {
			buf.WriteString("/" + cidr.Mask.String())
		}
		lines = append(lines, &DelclarationPropertyLine{
			Leading:      f.formatComment(cidr.Leading, "\n", 1),
			Trailing:     f.trailing(cidr.Trailing),
			Key:          buf.String(),
			EndCharacter: ";",
		})
	}

	// Append remaining lines
	if len(lines) > 0 {
		group.Lines = append(group.Lines, lines)
	}

	if f.conf.AlignTrailingComment {
		group.Align()
	}

	var buf bytes.Buffer
	buf.WriteString("acl " + decl.Name.Value + " {\n")
	buf.WriteString(group.String())
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return &Declaration{
		Type:   Acl,
		Name:   decl.Name.Value,
		Buffer: buf.String(),
	}
}

// Format backend declaration
func (f *Formatter) formatBackendDeclaration(decl *ast.BackendDeclaration) *Declaration {
	var buf bytes.Buffer

	buf.WriteString("backend " + decl.Name.Value + " {\n")
	buf.WriteString(f.formatBackendProperties(decl.Properties, 1))
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return &Declaration{
		Type:   Backend,
		Name:   decl.Name.Value,
		Buffer: buf.String(),
	}
}

// Format backend properties with align property names, trailing comment if needed
func (f *Formatter) formatBackendProperties(props []*ast.BackendProperty, nestLevel int) string {
	group := &GroupedLines{}
	lines := DelclarationPropertyLines{}

	for _, prop := range props {
		if prop.GetMeta().PreviousEmptyLines > 0 {
			if f.conf.AlignDeclarationProperty {
				lines.AlignKey()
			}
			if f.conf.SortDeclarationProperty {
				lines.Sort()
			}
			group.Lines = append(group.Lines, lines)
			lines = DelclarationPropertyLines{}
		}

		line := &DelclarationPropertyLine{
			Leading:  f.formatComment(prop.Leading, "\n", nestLevel),
			Trailing: f.trailing(prop.Trailing),
			Key:      f.indent(nestLevel) + "." + prop.Key.String(),
			Operator: " = ",
		}
		if po, ok := prop.Value.(*ast.BackendProbeObject); ok {
			line.Value = "{\n"
			line.Value += f.formatBackendProperties(po.Values, nestLevel+1)
			line.Value += f.indent(nestLevel) + "}"
			// probe property is object, semicolon is not needed
			line.isObject = true
		} else {
			line.Value = f.formatExpression(prop.Value).ChunkedString(prop.Nest, len(line.Key))
			line.EndCharacter = ";"
		}

		lines = append(lines, line)
	}

	// Append remaining lines
	if len(lines) > 0 {
		if f.conf.AlignDeclarationProperty {
			lines.AlignKey()
		}
		if f.conf.SortDeclarationProperty {
			lines.Sort()
		}
		group.Lines = append(group.Lines, lines)
	}

	if f.conf.AlignTrailingComment {
		group.Align()
	}

	return group.String()
}

// Format director declaration
func (f *Formatter) formatDirectorDeclaration(decl *ast.DirectorDeclaration) *Declaration {
	group := &GroupedLines{}
	lines := DelclarationPropertyLines{}

	for _, prop := range decl.Properties {
		if prop.GetMeta().PreviousEmptyLines > 0 {
			if f.conf.AlignDeclarationProperty {
				lines.AlignKey()
			}
			if f.conf.SortDeclarationProperty {
				lines.Sort()
			}
			group.Lines = append(group.Lines, lines)
			lines = DelclarationPropertyLines{}
		}
		line := &DelclarationPropertyLine{
			Leading:  f.formatComment(prop.GetMeta().Leading, "\n", 1),
			Trailing: f.trailing(prop.GetMeta().Trailing),
			Key:      f.indent(1),
		}
		switch t := prop.(type) {
		case *ast.DirectorBackendObject:
			line.Key += "{ "
			if f.conf.SortDeclarationProperty {
				sort.Slice(t.Values, func(i, j int) bool {
					return t.Values[i].Key.Value < t.Values[j].Key.Value
				})
			}
			for _, v := range t.Values {
				line.Key += fmt.Sprintf(".%s = %s; ", v.Key.Value, f.formatExpression(v.Value))
			}
			line.Key += "}"
			// Backend property is object, semicolon is not needed
			line.isObject = true
		case *ast.DirectorProperty:
			line.Key += "." + t.Key.Value
			line.Operator = " = "
			line.Value = t.Value.String()
			line.EndCharacter = ";"
		}
		lines = append(lines, line)
	}

	// Append remaining lines
	if len(lines) > 0 {
		if f.conf.AlignDeclarationProperty {
			lines.AlignKey()
		}
		if f.conf.SortDeclarationProperty {
			lines.Sort()
		}
		group.Lines = append(group.Lines, lines)
	}

	if f.conf.AlignTrailingComment {
		group.Align()
	}

	var buf bytes.Buffer
	buf.WriteString("director " + decl.Name.Value + " " + decl.DirectorType.Value + " {\n")
	buf.WriteString(group.String())
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return &Declaration{
		Type:   Director,
		Name:   decl.Name.Value,
		Buffer: buf.String(),
	}
}

// Format table declaration
func (f *Formatter) formatTableDeclaration(decl *ast.TableDeclaration) *Declaration {
	var buf bytes.Buffer

	buf.WriteString("table " + decl.Name.Value)
	if decl.ValueType != nil {
		buf.WriteString(" " + decl.ValueType.Value)
	}
	buf.WriteString(" {\n")
	buf.WriteString(f.formatTableProperties(decl.Properties))
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return &Declaration{
		Type:   Table,
		Name:   decl.Name.Value,
		Buffer: buf.String(),
	}
}

// Format table declaration
func (f *Formatter) formatTableProperties(props []*ast.TableProperty) string {
	group := &GroupedLines{}
	lines := DelclarationPropertyLines{}

	for _, prop := range props {
		if prop.Meta.PreviousEmptyLines > 0 {
			if f.conf.AlignDeclarationProperty {
				lines.AlignKey()
			}
			if f.conf.SortDeclarationProperty {
				lines.Sort()
			}
			group.Lines = append(group.Lines, lines)
			lines = DelclarationPropertyLines{}
		}
		line := &DelclarationPropertyLine{
			Leading:      f.formatComment(prop.Meta.Leading, "\n", 1),
			Trailing:     f.trailing(prop.Meta.Trailing),
			Operator:     ": ",
			Key:          f.indent(1) + f.formatString(prop.Key),
			Value:        f.formatExpression(prop.Value).String(),
			EndCharacter: ",",
		}
		lines = append(lines, line)
	}

	// Append remaining lines
	if len(lines) > 0 {
		if f.conf.AlignDeclarationProperty {
			lines.AlignKey()
		}
		if f.conf.SortDeclarationProperty {
			lines.Sort()
		}
		group.Lines = append(group.Lines, lines)
	}

	if f.conf.AlignTrailingComment {
		group.Align()
	}

	return group.String()
}

// Format penaltybox delclaration
func (f *Formatter) formatPenaltyboxDeclaration(decl *ast.PenaltyboxDeclaration) *Declaration {
	var buf bytes.Buffer

	buf.WriteString("penaltybox " + decl.Name.Value)
	buf.WriteString(" {")
	// penaltybox does not have properties
	if len(decl.Block.Infix) > 0 {
		buf.WriteString("\n")
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Block.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return &Declaration{
		Type:   Penaltybox,
		Name:   decl.Name.Value,
		Buffer: buf.String(),
	}
}

// Format ratecounter delclaration
func (f *Formatter) formatRatecounterDeclaration(decl *ast.RatecounterDeclaration) *Declaration {
	var buf bytes.Buffer

	buf.WriteString("ratecounter " + decl.Name.Value)
	buf.WriteString(" {")
	// ratecounter does not have properties
	if len(decl.Block.Infix) > 0 {
		buf.WriteString("\n")
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Block.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return &Declaration{
		Type:   Ratecounter,
		Name:   decl.Name.Value,
		Buffer: buf.String(),
	}
}

// Format subroutine declaration
func (f *Formatter) formatSubroutineDeclaration(decl *ast.SubroutineDeclaration) *Declaration {
	var buf bytes.Buffer

	buf.WriteString("sub " + decl.Name.Value + " ")
	buf.WriteString(f.formatBlockStatement(decl.Block))

	return &Declaration{
		Type:   Subroutine,
		Name:   decl.Name.Value,
		Buffer: buf.String(),
	}
}
