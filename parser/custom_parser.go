package parser

import (
	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/token"
)

type CustomParser interface {
	Ident() string
	Token() token.TokenType
	Parse(*Parser) (ast.CustomStatement, error)
}

func (p *Parser) ParseCustomToken() (ast.CustomStatement, error) {
	v, ok := p.customParsers[p.curToken.Token.Type]
	if !ok {
		return nil, UnexpectedToken(p.curToken)
	}
	// Parse tokens by CustomParser implementation
	return v.Parse(p)
}
