package codec

import (
	"bytes"

	"github.com/ysugimoto/falco/ast"
)

func (c *Encoder) encodeAclDeclaration(acl *ast.AclDeclaration) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(acl.Name).Encode())
	for _, cidr := range acl.CIDRs {
		w.Write(c.encodeAclCidr(cidr).Encode())
	}
	w.Write(end())

	return &Frame{
		frameType: ACL_DECLARATION,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeAclCidr(cidr *ast.AclCidr) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	if cidr.Inverse != nil {
		w.Write(c.encodeBoolean(cidr.Inverse).Encode())
	}
	w.Write(c.encodeIP(cidr.IP).Encode())
	if cidr.Mask != nil {
		w.Write(c.encodeInteger(cidr.Mask).Encode())
	}

	return &Frame{
		frameType: ACL_CIDR,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeBackendDeclaration(b *ast.BackendDeclaration) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(b.Name).Encode())
	for _, prop := range b.Properties {
		w.Write(c.encodeBackendProperty(prop).Encode())
	}
	w.Write(end())

	return &Frame{
		frameType: BACKEND_DECLARATION,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeBackendProperty(prop *ast.BackendProperty) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(prop.Key).Encode())
	if probe, ok := prop.Value.(*ast.BackendProbeObject); ok {
		for _, p := range probe.Values {
			var bin []byte
			bin = append(bin, c.encodeIdent(p.Key).Encode()...)
			bin = append(bin, c.encodeExpression(p.Value).Encode()...)
			w.Write((&Frame{frameType: BACKEND_PROPERTY, buffer: bin}).Encode())
		}
		w.Write(end())

		return &Frame{
			frameType: BACKEND_PROBE,
			buffer:    w.Bytes(),
		}
	}

	w.Write(c.encodeExpression(prop.Value).Encode())

	return &Frame{
		frameType: BACKEND_PROPERTY,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeDirectorDeclaration(d *ast.DirectorDeclaration) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(d.Name).Encode())
	w.Write(c.encodeIdent(d.DirectorType).Encode())

	for _, prop := range d.Properties {
		w.Write(c.encodeDirectorProperty(prop).Encode())
	}
	w.Write(end())

	return &Frame{
		frameType: DIRECTOR_DECLARATION,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeDirectorProperty(prop ast.Expression) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	switch t := prop.(type) {
	case *ast.DirectorBackendObject:
		return c.encodeDirectorBackend(t)
	case *ast.DirectorProperty:
		w.Write(c.encodeIdent(t.Key).Encode())
		w.Write(c.encodeExpression(t.Value).Encode())

		return &Frame{
			frameType: DIRECTOR_PROPERTY,
			buffer:    w.Bytes(),
		}
	default:
		return &Frame{
			frameType: UNKNOWN,
			buffer:    w.Bytes(),
		}
	}
}
func (c *Encoder) encodeDirectorBackend(backend *ast.DirectorBackendObject) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	for _, v := range backend.Values {
		w.Write(c.encodeDirectorProperty(v).Encode())
	}
	w.Write(end())

	return &Frame{
		frameType: DIRECTOR_BACKEND,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodePenaltyboxDelcaration(p *ast.PenaltyboxDeclaration) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(p.Name).Encode())

	// Block statement must be empty so skip encode

	return &Frame{
		frameType: PENALTYBOX_DECLARATION,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeRatecounterDeclaration(r *ast.RatecounterDeclaration) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(r.Name).Encode())

	// Block statement must be empty so skip encode

	return &Frame{
		frameType: RATECOUNTER_DECLARATION,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeSubroutineDeclaration(sub *ast.SubroutineDeclaration) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(sub.Name).Encode())
	if sub.ReturnType != nil {
		w.Write(c.encodeIdent(sub.ReturnType).Encode())
	}
	w.Write(c.encodeBlockStatement(sub.Block).Encode())

	return &Frame{
		frameType: SUBROUTINE_DECLARATION,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeTableDeclaration(tbl *ast.TableDeclaration) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(tbl.Name).Encode())
	if tbl.ValueType != nil {
		w.Write(c.encodeIdent(tbl.ValueType).Encode())
	}

	for _, prop := range tbl.Properties {
		w.Write(c.encodeTableProperty(prop).Encode())
	}
	w.Write(end())

	return &Frame{
		frameType: TABLE_DECLARATION,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeTableProperty(prop *ast.TableProperty) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeString(prop.Key).Encode())
	w.Write(c.encodeExpression(prop.Value).Encode())

	return &Frame{
		frameType: TABLE_PROPERTY,
		buffer:    w.Bytes(),
	}
}
