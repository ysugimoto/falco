package codec

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

func (c *Codec) decodeAclDeclaration(b []byte) (*ast.AclDeclaration, error) {
	at, bin, err := unpack(b)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if at != IDENT_VALUE {
	}
}
