package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type AclDeclaration struct {
	*Meta
	Name  *Ident
	CIDRs []*AclCidr
}

func (a *AclDeclaration) statement()            {}
func (a *AclDeclaration) expression()           {}
func (a *AclDeclaration) GetToken() token.Token { return a.Token }
func (a *AclDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(a.LeadingComment())
	buf.WriteString("acl ")
	buf.WriteString(a.Name.String())
	buf.WriteString(" {\n")
	for _, cidr := range a.CIDRs {
		buf.WriteString(cidr.String() + "\n")
	}
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

func (c *AclCidr) GetToken() token.Token { return c.Token }
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
