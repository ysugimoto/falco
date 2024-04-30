package ast

import (
	"bytes"
)

type AclDeclaration struct {
	*Meta
	Name  *Ident
	CIDRs []*AclCidr
}

func (a *AclDeclaration) statement()     {}
func (a *AclDeclaration) expression()    {}
func (a *AclDeclaration) GetMeta() *Meta { return a.Meta }
func (a *AclDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(a.LeadingComment(lineFeed))
	buf.WriteString("acl ")
	buf.WriteString(a.Name.String())
	buf.WriteString(" {\n")
	for _, cidr := range a.CIDRs {
		buf.WriteString(cidr.String())
		buf.WriteString("\n")
	}
	buf.WriteString(a.InfixComment(lineFeed))
	buf.WriteString("}")
	buf.WriteString(a.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}

type AclCidr struct {
	*Meta
	Inverse *Boolean
	IP      *IP
	Mask    *Integer
}

func (c *AclCidr) GetMeta() *Meta { return c.Meta }
func (c *AclCidr) String() string {
	var buf bytes.Buffer

	buf.WriteString(c.LeadingComment(lineFeed))
	buf.WriteString(indent(c.Nest))
	if c.Inverse != nil && c.Inverse.Value {
		buf.WriteString("!")
	}
	buf.WriteString(c.IP.LeadingComment(inline))
	buf.WriteString(`"` + c.IP.Value + `"`)
	if c.Mask != nil {
		buf.WriteString("/" + c.Mask.String())
	}
	buf.WriteString(c.IP.TrailingComment(inline))
	buf.WriteString(";")
	buf.WriteString(c.TrailingComment(inline))

	return buf.String()
}
