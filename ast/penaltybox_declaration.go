package ast

import "bytes"

type PenaltyboxDeclaration struct {
	*Meta
	Name  *Ident
	Block *BlockStatement
}

func (p *PenaltyboxDeclaration) statement()     {}
func (p *PenaltyboxDeclaration) GetMeta() *Meta { return p.Meta }
func (p *PenaltyboxDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(p.LeadingComment())
	buf.WriteString("penaltybox ")
	buf.WriteString(p.Name.String())
	buf.WriteString(" " + p.Block.String())
	buf.WriteString(p.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
