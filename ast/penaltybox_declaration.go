package ast

import "bytes"

type PenaltyboxDeclaration struct {
	*Meta
	Name  *Ident
	Block *BlockStatement
}

func (p *PenaltyboxDeclaration) Statement()     {}
func (p *PenaltyboxDeclaration) GetMeta() *Meta { return p.Meta }
func (p *PenaltyboxDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(p.LeadingComment(lineFeed))
	buf.WriteString("penaltybox")
	buf.WriteString(padding(p.Name.String()))
	buf.WriteString(p.Block.String())
	buf.WriteString(p.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
