package codec

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

func (c *Decoder) decodeAclDeclaration() (*ast.AclDeclaration, error) {
	var err error
	acl := &ast.AclDeclaration{}

	acl.Name, err = c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto OUT
		case FIN:
			return nil, unexpectedFinByte()
		case ACL_CIDR:
			cidr, err := c.decodeAclCidr()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			acl.CIDRs = append(acl.CIDRs, cidr)
		default:
			return nil, typeMismatch(ACL_CIDR, frame.Type())
		}
	}
OUT:
	return acl, nil
}

func (c *Decoder) decodeAclCidr() (*ast.AclCidr, error) {
	var err error
	cidr := &ast.AclCidr{}

	if c.peekFrameIs(BOOL_VALUE) {
		cidr.Inverse, err = c.decodeBoolean(c.nextFrame())
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	cidr.IP, err = c.decodeIP(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if c.peekFrameIs(INTEGER_VALUE) {
		cidr.Mask, err = c.decodeInteger(c.nextFrame())
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return cidr, nil
}

func (c *Decoder) decodeBackendDeclaration() (*ast.BackendDeclaration, error) {
	var err error
	backend := &ast.BackendDeclaration{}

	backend.Name, err = c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto OUT
		case FIN:
			return nil, unexpectedFinByte()
		case BACKEND_PROPERTY:
			prop := &ast.BackendProperty{}
			prop.Key, err = c.decodeIdent(c.nextFrame())
			if err != nil {
				return nil, errors.WithStack(err)
			}
			prop.Value, err = c.decodeExpression(c.nextFrame())
			if err != nil {
				return nil, errors.WithStack(err)
			}
			backend.Properties = append(backend.Properties, prop)
		case BACKEND_PROBE:
			prop := &ast.BackendProperty{}
			prop.Key, err = c.decodeIdent(c.nextFrame())
			if err != nil {
				return nil, errors.WithStack(err)
			}
			prop.Value, err = c.decodeBackendProbeObject()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			backend.Properties = append(backend.Properties, prop)
		default:
			return nil, typeMismatch(BACKEND_PROPERTY, frame.Type())
		}
	}
OUT:
	return backend, nil
}

func (c *Decoder) decodeBackendProbeObject() (*ast.BackendProbeObject, error) {
	var err error
	probe := &ast.BackendProbeObject{}

	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto OUT
		case FIN:
			return nil, unexpectedFinByte()
		case BACKEND_PROPERTY:
			prop := &ast.BackendProperty{}
			prop.Key, err = c.decodeIdent(c.nextFrame())
			if err != nil {
				return nil, errors.WithStack(err)
			}
			prop.Value, err = c.decodeExpression(c.nextFrame())
			if err != nil {
				return nil, errors.WithStack(err)
			}
			probe.Values = append(probe.Values, prop)
		default:
			return nil, typeMismatch(BACKEND_PROPERTY, frame.Type())
		}
	}
OUT:
	return probe, nil
}

func (c *Decoder) decodeDirectorDeclaration() (*ast.DirectorDeclaration, error) {
	var err error
	director := &ast.DirectorDeclaration{}

	director.Name, err = c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	director.DirectorType, err = c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto OUT
		case FIN:
			return nil, unexpectedFinByte()
		case DIRECTOR_PROPERTY:
			prop := &ast.DirectorProperty{}
			prop.Key, err = c.decodeIdent(c.nextFrame())
			if err != nil {
				return nil, errors.WithStack(err)
			}
			prop.Value, err = c.decodeExpression(c.nextFrame())
			if err != nil {
				return nil, errors.WithStack(err)
			}
			director.Properties = append(director.Properties, prop)
		case DIRECTOR_BACKEND:
			backend, err := c.decodeDirectorBackendObject()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			director.Properties = append(director.Properties, backend)
		default:
			return nil, typeMismatch(DIRECTOR_PROPERTY, frame.Type())
		}
	}
OUT:
	return director, nil
}

func (c *Decoder) decodeDirectorBackendObject() (*ast.DirectorBackendObject, error) {
	var err error
	backend := &ast.DirectorBackendObject{}

	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto OUT
		case FIN:
			return nil, unexpectedFinByte()
		case DIRECTOR_PROPERTY:
			prop := &ast.DirectorProperty{}
			prop.Key, err = c.decodeIdent(c.nextFrame())
			if err != nil {
				return nil, errors.WithStack(err)
			}
			prop.Value, err = c.decodeExpression(c.nextFrame())
			if err != nil {
				return nil, errors.WithStack(err)
			}
			backend.Values = append(backend.Values, prop)
		default:
			return nil, typeMismatch(DIRECTOR_PROPERTY, frame.Type())
		}
	}
OUT:
	return backend, nil
}

func (c *Decoder) decodePenaltyboxDeclaration() (*ast.PenaltyboxDeclaration, error) {
	name, err := c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.PenaltyboxDeclaration{
		Name:  name,
		Block: &ast.BlockStatement{},
	}, nil
}

func (c *Decoder) decodeRatecounterDeclaration() (*ast.RatecounterDeclaration, error) {
	name, err := c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.RatecounterDeclaration{
		Name:  name,
		Block: &ast.BlockStatement{},
	}, nil
}

func (c *Decoder) decodeSubroutineDeclaration() (*ast.SubroutineDeclaration, error) {
	var err error
	sub := &ast.SubroutineDeclaration{
		Block: &ast.BlockStatement{},
	}

	if sub.Name, err = c.decodeIdent(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}
	// Functional subroutine has return type ident
	if c.peekFrameIs(IDENT_VALUE) {
		if sub.ReturnType, err = c.decodeIdent(c.nextFrame()); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if !c.peekFrameIs(BLOCK_STATEMENT) {
		return nil, typeMismatch(BLOCK_STATEMENT, c.peekFrame().Type())
	}
	c.nextFrame() // point to BLOCK_STATEMENT frame

	if sub.Block, err = c.decodeBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}

	return sub, nil
}

func (c *Decoder) decodeTableDeclaration() (*ast.TableDeclaration, error) {
	var err error
	tbl := &ast.TableDeclaration{}

	if tbl.Name, err = c.decodeIdent(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}
	if c.peekFrameIs(IDENT_VALUE) {
		if tbl.ValueType, err = c.decodeIdent(c.nextFrame()); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto OUT
		case FIN:
			return nil, unexpectedFinByte()
		case TABLE_PROPERTY:
			prop := &ast.TableProperty{}
			if prop.Key, err = c.decodeString(c.nextFrame()); err != nil {
				return nil, errors.WithStack(err)
			}
			if prop.Value, err = c.decodeExpression(c.nextFrame()); err != nil {
				return nil, errors.WithStack(err)
			}
			tbl.Properties = append(tbl.Properties, prop)
		default:
			return nil, typeMismatch(TABLE_PROPERTY, frame.Type())
		}
	}
OUT:

	return tbl, nil
}
