package parser

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

func (p *Parser) parseIdent() *ast.Ident {
	i := &ast.Ident{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}
	p.attachUnboundComments(i, AttachmentLeading, false)
	p.attachUnboundComments(i, AttachmentTrailing, true)
	return i
}

func (p *Parser) parseIP() *ast.IP {
	return &ast.IP{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}
}

func (p *Parser) parseString() (*ast.String, error) {
	var err error
	parsed := p.curToken.Token.Literal
	// Escapes are only expanded in double-quoted strings.
	if p.curToken.Token.Offset == 2 {
		parsed, err = decodeStringEscapes(parsed)
		if err != nil {
			return nil, errors.WithStack(InvalidEscape(p.curToken, err.Error()))
		}
	}

	return &ast.String{
		Meta:  p.curToken,
		Value: parsed,
	}, nil
}

func (p *Parser) parseInteger() (*ast.Integer, error) {
	v, err := strconv.ParseInt(p.curToken.Token.Literal, 10, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "INTEGER"))
	}

	return &ast.Integer{
		Meta:  p.curToken,
		Value: v,
	}, nil
}

func (p *Parser) parseFloat() (*ast.Float, error) {
	v, err := strconv.ParseFloat(p.curToken.Token.Literal, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "FLOAT"))
	}

	return &ast.Float{
		Meta:  p.curToken,
		Value: v,
	}, nil
}

// nolint: unparam
func (p *Parser) parseBoolean() *ast.Boolean {
	return &ast.Boolean{
		Meta:  p.curToken,
		Value: p.curToken.Token.Type == token.TRUE,
	}
}

func (p *Parser) parseRTime() (*ast.RTime, error) {
	var value string

	literal := p.curToken.Token.Literal
	switch {
	case strings.HasSuffix(literal, "ms"):
		value = strings.TrimSuffix(literal, "ms")
	case strings.HasSuffix(literal, "s"):
		value = strings.TrimSuffix(literal, "s")
	case strings.HasSuffix(literal, "m"):
		value = strings.TrimSuffix(literal, "m")
	case strings.HasSuffix(literal, "h"):
		value = strings.TrimSuffix(literal, "h")
	case strings.HasSuffix(literal, "d"):
		value = strings.TrimSuffix(literal, "d")
	case strings.HasSuffix(literal, "y"):
		value = strings.TrimSuffix(literal, "y")
	default:
		return nil, errors.WithStack(TypeConversionError(p.curToken, "RTIME"))
	}

	if _, err := strconv.ParseFloat(value, 64); err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "RTIME"))
	}
	return &ast.RTime{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}, nil
}
