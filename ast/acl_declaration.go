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

	buf.WriteString(a.LeadingComment())
	buf.WriteString("acl ")
	buf.WriteString(a.Name.String())
	buf.WriteString(" {\n")
	for _, cidr := range a.CIDRs {
		buf.WriteString(cidr.String() + "\n")
	}
	buf.WriteString(a.InfixComment())
	buf.WriteString("}")
	buf.WriteString(a.TrailingComment())
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

	buf.WriteString(c.LeadingComment())
	buf.WriteString(indent(c.Nest))
	if c.Inverse != nil && c.Inverse.Value {
		buf.WriteString("!")
	}
	buf.WriteString(`"` + c.IP.String() + `"`)
	if c.Mask != nil {
		buf.WriteString("/" + c.Mask.String())
	}
	buf.WriteString(";")
	buf.WriteString(c.TrailingComment())

	return buf.String()
}
