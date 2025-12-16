package formatter

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

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
		buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
		buf.Reset()
		buf.WriteString(f.indent(1))

		if cidr.Inverse != nil && cidr.Inverse.Value {
			buf.WriteString("!")
		}
		if v := f.formatComment(cidr.IP.Leading, " ", 0); v != "" {
			buf.WriteString(" " + v)
		}
		buf.WriteString(`"` + cidr.IP.Value + `"`)
		if cidr.Mask != nil {
			buf.WriteString("/" + cidr.Mask.String())
		}
		if v := f.formatComment(cidr.IP.Trailing, " ", 0); v != "" {
			buf.WriteString(" " + v)
		}
		lines = append(lines, &DelclarationPropertyLine{
			Leading:      f.formatComment(cidr.Leading, "\n", 1),
			Trailing:     f.trailing(cidr.Trailing),
			Key:          buf.String(),
			EndCharacter: ";",
		})
		bufferPool.Put(buf)
	}

	// Append remaining lines
	if len(lines) > 0 {
		group.Lines = append(group.Lines, lines)
	}

	if f.conf.AlignTrailingComment {
		group.Align()
	}

	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	buf.WriteString("acl " + decl.Name.String() + " {\n")
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
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	buf.WriteString("backend " + decl.Name.String() + " {\n")
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
				if v := f.formatComment(v.Leading, " ", 0); v != "" {
					line.Key += v
				}
				line.Key += fmt.Sprintf(".%s = %s; ", v.Key.String(), v.Value.String())
			}
			if len(t.Infix) > 0 {
				line.Key += f.formatComment(t.Infix, " ", 0)
			}
			line.Key += "}"
			// Backend property is object, semicolon is not needed
			line.isObject = true
		case *ast.DirectorProperty:
			line.Key += "." + t.Key.String()
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

	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	buf.WriteString("director " + decl.Name.String() + " " + decl.DirectorType.String() + " {\n")
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
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	buf.WriteString("table " + decl.Name.String())
	if decl.ValueType != nil {
		buf.WriteString(" " + decl.ValueType.String())
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
		if prop.PreviousEmptyLines > 0 {
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
			Leading:      f.formatComment(prop.Leading, "\n", 1),
			Trailing:     f.trailing(prop.Trailing),
			Operator:     ": ",
			Key:          f.indent(1) + prop.Key.String(),
			Value:        prop.Value.String(),
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
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	buf.WriteString("penaltybox " + decl.Name.String())
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
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	buf.WriteString("ratecounter " + decl.Name.String())
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
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	buf.WriteString("sub " + decl.Name.String())

	// Format subroutine parameters if exists
	if len(decl.Parameters) > 0 {
		args := make([]string, len(decl.Parameters))
		for i, param := range decl.Parameters {
			args[i] = param.Type.String() + " " + param.Name.String()
		}
		buf.WriteString("(" + strings.Join(args, ", ") + ")")
	}

	buf.WriteString(" ")

	// Functional Subroutine
	if decl.ReturnType != nil {
		buf.WriteString(decl.ReturnType.String() + " ")
		f.isFunctionalSubroutine = true // flag turns on
		defer func() {
			f.isFunctionalSubroutine = false
		}()
	}
	buf.WriteString(f.formatBlockStatement(decl.Block))

	return &Declaration{
		Type:   Subroutine,
		Name:   decl.Name.Value,
		Buffer: buf.String(),
	}
}
