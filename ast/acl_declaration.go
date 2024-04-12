package ast

import (
	"bytes"
)

// Acl declaration node
// Comment placement specification:
//
// /* PlaceLeading */
// acl /* PlaceAclBeforeName */ <name> /* PlaceAclAfterName */ {
//   <AclCidr>...
// }  /* PlaceTrailing */
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
	if v := a.Comment(PlaceAclBeforeName); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(a.Name.String())
	if v := a.Comment(PlaceAclAfterName); v != "" {
		buf.WriteString(v)
	}
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

// Acl CIDR line node
// Comment placement specification:
//
// /* PlaceLeading */
// <inverse> /* PlaceAclCidrAfterInverse */ <IP>/<Mask>; /* PlaceTrailing */
//
// Note that if inverse sign does not exist, /* after_inverse */ comment will be integrated into leading comment.
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
	if v := c.Comment(PlaceAclCidrAfterInverse); v != "" {
		buf.WriteString(" " + v + " ")
	}
	buf.WriteString(`"` + c.IP.String() + `"`)
	if c.Mask != nil {
		buf.WriteString("/" + c.Mask.String())
	}
	buf.WriteString(";")
	buf.WriteString(c.TrailingComment())

	return buf.String()
}
