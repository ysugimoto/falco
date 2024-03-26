package formatter

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/ysugimoto/falco/ast"
)

func (f *Formatter) formatAclDeclaration(decl *ast.AclDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(decl.Leading, "\n", 0))
	buf.WriteString("acl " + decl.Name.Value + " {\n")
	for _, cidr := range decl.CIDRs {
		buf.WriteString(f.formatComment(cidr.Leading, "\n", 1))
		buf.WriteString(f.indent(1))
		if cidr.Inverse != nil && cidr.Inverse.Value {
			buf.WriteString("!")
			if f.conf.AclInverseWithSpace {
				buf.WriteString(" ")
			}
		}
		buf.WriteString(`"` + cidr.IP.String() + `"`)
		if cidr.Mask != nil {
			buf.WriteString("/" + cidr.Mask.String())
		}
		buf.WriteString(";")
		buf.WriteString(f.trailing(cidr.Trailing))
		buf.WriteString("\n")
	}
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")
	buf.WriteString(f.trailing(decl.Trailing))

	return buf.String()
}

func (f *Formatter) formatBackendDeclaration(decl *ast.BackendDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(decl.Leading, "\n", 0))
	buf.WriteString("backend " + decl.Name.Value + " {\n")
	buf.WriteString(f.formatBackendProperties(decl.Properties, 1))
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")
	buf.WriteString(f.trailing(decl.Trailing))

	return buf.String()
}

func (f *Formatter) formatBackendProperties(props []*ast.BackendProperty, nestLevel int) string {
	var buf bytes.Buffer
	var maxPropLength int

	if f.conf.SortDeclarationProperty {
		sort.Slice(props, func(i, j int) bool {
			if props[i].Key.String() == "probe" {
				return false
			}
			return props[i].Key.String() < props[j].Key.String()
		})
	}

	for i := range props {
		if len(props[i].Key.String()) > maxPropLength {
			maxPropLength = len(props[i].Key.String())
		}
	}

	for _, prop := range props {
		buf.WriteString(f.formatComment(prop.Leading, "\n", nestLevel))
		buf.WriteString(f.indent(nestLevel))
		if f.conf.AlignDeclarationProperty {
			format := fmt.Sprintf("%%-%ds", maxPropLength)
			buf.WriteString(fmt.Sprintf("."+format+" = ", prop.Key.String()))
		} else {
			buf.WriteString(fmt.Sprintf(".%s = ", prop.Key.String()))
		}
		if po, ok := prop.Value.(*ast.BackendProbeObject); ok {
			buf.WriteString("{\n")
			buf.WriteString(f.formatBackendProperties(po.Values, nestLevel+1))
			buf.WriteString(f.indent(nestLevel) + "}")
		} else {
			buf.WriteString(f.formatExpression(prop.Value))
			buf.WriteString(";")
		}
		buf.WriteString(f.trailing(prop.Trailing))
		buf.WriteString("\n")
	}
	return buf.String()
}

func (f *Formatter) formatDirectorDeclaration(decl *ast.DirectorDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(decl.Leading, "\n", 0))
	buf.WriteString("director " + decl.Name.Value + " " + decl.DirectorType.Value + " {\n")
	for _, prop := range decl.Properties {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatDirectorProperty(prop.(*ast.DirectorBackendObject)))
		buf.WriteString("\n")
	}
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")
	buf.WriteString(f.trailing(decl.Trailing))

	return buf.String()
}

func (f *Formatter) formatDirectorProperty(prop *ast.DirectorBackendObject) string {
	var buf bytes.Buffer

	if f.conf.SortDeclarationProperty {
		sort.Slice(prop.Values, func(i, j int) bool {
			return prop.Values[i].Key.Value < prop.Values[j].Key.Value
		})
	}

	buf.WriteString(f.formatComment(prop.Leading, "\n", 0))
	buf.WriteString("{ ")
	for _, v := range prop.Values {
		buf.WriteString(fmt.Sprintf(".%s = %s; ", v.Key.Value, f.formatExpression(v.Value)))
	}
	buf.WriteString("}")
	buf.WriteString(f.trailing(prop.Trailing))

	return buf.String()
}

func (f *Formatter) formatTableDeclaration(decl *ast.TableDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(decl.Leading, "\n", 0))
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
	buf.WriteString(f.trailing(decl.Trailing))

	return buf.String()
}

func (f *Formatter) formatTableProperties(props []*ast.TableProperty) string {
	var buf bytes.Buffer
	var maxPropLength int

	if f.conf.SortDeclarationProperty {
		sort.Slice(props, func(i, j int) bool {
			return props[i].Key.Value < props[j].Key.Value
		})
	}

	for i := range props {
		if len(props[i].Key.String()) > maxPropLength {
			maxPropLength = len(props[i].Key.String())
		}
	}

	for _, prop := range props {
		buf.WriteString(f.formatComment(prop.Leading, "\n", 0))
		buf.WriteString(f.indent(1))
		if f.conf.AlignDeclarationProperty {
			format := fmt.Sprintf("%%-%ds", maxPropLength)
			buf.WriteString(fmt.Sprintf(format+": ", f.formatString(prop.Key)))
		} else {
			buf.WriteString(fmt.Sprintf("%s: ", f.formatString(prop.Key)))
		}
		buf.WriteString(f.formatExpression(prop.Value))
		buf.WriteString(",")
		buf.WriteString(f.trailing(prop.Trailing))
		buf.WriteString("\n")
	}

	return buf.String()
}

func (f *Formatter) formatPenaltyboxDeclaration(decl *ast.PenaltyboxDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(decl.Leading, "\n", 0))
	buf.WriteString("penaltybox " + decl.Name.Value)
	buf.WriteString(" {\n")
	// penaltybox does not have properties
	if len(decl.Block.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Block.Infix, "\n", 0))
	}
	buf.WriteString("}")
	buf.WriteString(f.trailing(decl.Block.Trailing))

	return buf.String()
}

func (f *Formatter) formatRatecounterDeclaration(decl *ast.RatecounterDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(decl.Leading, "\n", 0))
	buf.WriteString("ratecounter " + decl.Name.Value)
	buf.WriteString(" {\n")
	// ratecounter does not have properties
	if len(decl.Block.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Block.Infix, "\n", 0))
	}
	buf.WriteString("}")
	buf.WriteString(f.trailing(decl.Block.Trailing))

	return buf.String()
}

func (f *Formatter) formatSubroutineDeclaration(decl *ast.SubroutineDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString(f.formatComment(decl.Leading, "\n", 0))
	buf.WriteString("sub " + decl.Name.Value + " ")
	buf.WriteString(f.formatBlockStatement(decl.Block, false))

	return buf.String()
}
