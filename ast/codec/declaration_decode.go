package codec

import (
	"bufio"
	"io"

	"github.com/ysugimoto/falco/ast"
)

func (c *Decoder) decodeAclDeclaration(stream io.Reader) (*ast.AclDeclaration, error) {
	var err error

	acl := &ast.AclDeclaration{}
	r := bufio.NewReader(stream)

	if acl.Name, err = unpackIdent(r); err != nil {
		return nil, err
	}
	for !c.peekTypeIs(r, END) {
		at, bin, err := unpack(r)
		if err != nil {
			return nil, err
		}
		if at != ACL_CIDR {
			return nil, typeMismatch(ACL_CIDR, at)
		}
		cr := bufio.NewReader(bin)
		cidr := &ast.AclCidr{}
		if c.peekTypeIs(cr, BOOL_VALUE) {
			if cidr.Inverse, err = unpackBoolean(cr); err != nil {
				return nil, err
			}
		}
		if cidr.IP, err = unpackIP(cr); err != nil {
			return nil, err
		}
		if c.peekTypeIs(cr, INTEGER_VALUE) {
			if cidr.Mask, err = unpackInteger(cr); err != nil {
				return nil, err
			}
		}
		acl.CIDRs = append(acl.CIDRs, cidr)
	}

	// Discard END type
	unpack(r) // nolint:errcheck

	return acl, nil
}
