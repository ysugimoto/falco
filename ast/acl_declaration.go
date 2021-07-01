package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type AclDeclaration struct {
	Token    token.Token
	Name     *Ident
	CIDRs    []*AclCidr
	Comments Comments
}

func (a *AclDeclaration) statement()            {}
func (a *AclDeclaration) expression()           {}
func (a *AclDeclaration) GetComments() string   { return a.Comments.String() }
func (a *AclDeclaration) GetToken() token.Token { return a.Token }
func (a *AclDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(a.Comments.String())
	buf.WriteString("acl ")
	buf.WriteString(a.Name.String())
	buf.WriteString(" {\n")
	for _, cidr := range a.CIDRs {
		buf.WriteString("  " + cidr.String() + "\n")
	}
	buf.WriteString("}\n")

	return buf.String()
}

type AclCidr struct {
	Token    token.Token
	Inverse  *Boolean
	IP       *IP
	Mask     *Integer
	Comments Comments
}

func (c *AclCidr) expression()           {}
func (c *AclCidr) GetToken() token.Token { return c.Token }
func (c *AclCidr) String() string {
	var buf bytes.Buffer

	buf.WriteString(c.Comments.String())
	if c.Inverse != nil && c.Inverse.Value {
		buf.WriteString("!")
	}
	buf.WriteString(c.IP.String())
	if c.Mask != nil {
		buf.WriteString("/" + c.Mask.String())
	}
	buf.WriteString(";")

	return buf.String()
}
