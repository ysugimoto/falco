package codec

import (
	"bytes"

	"github.com/ysugimoto/falco/ast"
)

func (c *Codec) encodeAclDeclaration(acl *ast.AclDeclaration) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(acl.Name.Value))
	for _, cidr := range acl.CIDRs {
		b := encodePool.Get().(*bytes.Buffer)
		b.Reset()

		if cidr.Inverse != nil {
			b.Write(packBoolean(cidr.Inverse.Value))
		}
		b.Write(packIP(cidr.IP.Value))
		if cidr.Mask != nil {
			b.Write(packInteger(cidr.Mask.Value))
		}
		w.Write(pack(ACL_CIDR, b.Bytes()))
		encodePool.Put(b)
	}
	w.Write(end())

	return pack(ACL_DECLARATION, w.Bytes())
}

func (c *Codec) encodeBackendDeclaration(b *ast.BackendDeclaration) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(b.Name.Value))
	for _, prop := range b.Properties {
		b := encodePool.Get().(*bytes.Buffer)
		b.Reset()

		b.Write(packIdent(prop.Key.Value))
		if probe, ok := prop.Value.(*ast.BackendProbeObject); ok {
			for _, p := range probe.Values {
				b.Write(packIdent(p.Key.Value))
				b.Write(c.encodeExpression(p.Value))
			}
			w.Write(pack(BACKEND_PROBE, b.Bytes()))
			encodePool.Put(b)
			continue
		}
		b.Write(c.encodeExpression(prop.Value))
		w.Write(pack(BACKEND_PROPERTY, b.Bytes()))
		encodePool.Put(b)
	}
	w.Write(end())

	return pack(BACKEND_DECLARATION, w.Bytes())
}

func (c *Codec) encodeDirectorDeclaration(d *ast.DirectorDeclaration) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(d.Name.Value))
	w.Write(packIdent(d.DirectorType.Value))

	for _, prop := range d.Properties {
		b := encodePool.Get().(*bytes.Buffer)
		b.Reset()

		switch t := prop.(type) {
		case *ast.DirectorBackendObject:
			for _, v := range t.Values {
				b.Write(packIdent(v.Key.Value))
				b.Write(c.encodeExpression(v.Value))
			}

			w.Write(pack(DIRECTOR_BACKEND, b.Bytes()))
		case *ast.DirectorProperty:
			b.Write(packIdent(t.Key.Value))
			b.Write(c.encodeExpression(t.Value))

			w.Write(pack(BACKEND_PROPERTY, b.Bytes()))
		}
		encodePool.Put(b)
	}
	w.Write(end())

	return pack(DIRECTOR_DECLARATION, w.Bytes())
}

func (c *Codec) encodePenaltyboxDelcaration(p *ast.PenaltyboxDeclaration) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(p.Name.Value))
	return pack(PENALTYBOX_DECLARATION, w.Bytes())
}

func (c *Codec) encodeRatecounterDeclaration(r *ast.RatecounterDeclaration) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(r.Name.Value))
	return pack(RATECOUNTER_DECLARATION, w.Bytes())
}

func (c *Codec) encodeSubroutineDeclaration(sub *ast.SubroutineDeclaration) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(sub.Name.Value))
	for _, stmt := range sub.Block.Statements {
		w.Write(c.Encode(stmt))
	}
	w.Write(end())
	if sub.ReturnType != nil {
		w.Write(packIdent(sub.ReturnType.Value))
	}
	return pack(SUBROUTINE_DECLARATION, w.Bytes())
}

func (c *Codec) encodeTableDeclaration(tbl *ast.TableDeclaration) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(tbl.Name.Value))
	vt := "STRING"
	if tbl.ValueType != nil {
		vt = tbl.ValueType.Value
	}
	w.Write(packIdent(vt))

	for _, prop := range tbl.Properties {
		b := encodePool.Get().(*bytes.Buffer)
		b.Reset()

		b.Write(packString(prop.Key.Value))
		b.Write(c.encodeExpression(prop.Value))

		w.Write(pack(TABLE_PROPERTY, b.Bytes()))
		encodePool.Put(b)
	}
	w.Write(end())

	return pack(TABLE_DECLARATION, w.Bytes())
}
