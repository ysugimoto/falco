package parser

import (
	"github.com/ysugimoto/falco/ast"
)

type CustomParser interface {
	Literal() string
	Parse(*Parser) (ast.CustomStatement, error)
}

func (p *Parser) ParseCustomToken() (ast.CustomStatement, error) {
	v, ok := p.customParsers[p.curToken.Token.Literal]
	if !ok {
		return nil, UnexpectedToken(p.curToken)
	}
	// Parse tokens by CustomParser implementation
	return v.Parse(p)
}
