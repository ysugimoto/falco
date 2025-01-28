package parser

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

func (p *Parser) ParseIdent() *ast.Ident {
	return &ast.Ident{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}
}

func (p *Parser) ParseIP() *ast.IP {
	return &ast.IP{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}
}

func (p *Parser) ParseLongString() (*ast.String, error) {
	if !p.PeekTokenIs(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.STRING))
	}

	openToken := p.curToken
	delimiter := p.curToken.Token.Literal
	p.NextToken()

	str, err := p.ParseString()
	str.LongString = true
	str.Delimiter = delimiter

	if !p.PeekTokenIs(token.CLOSE_LONG_STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.CLOSE_LONG_STRING))
	}
	// Check open and close delimiter string is the same
	if delimiter != p.peekToken.Token.Literal {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.CLOSE_LONG_STRING))
	}

	str.GetMeta().Leading = openToken.Leading
	str.GetMeta().Trailing = p.peekToken.Trailing
	p.NextToken()

	return str, err
}

func (p *Parser) ParseString() (*ast.String, error) {
	var err error
	Parsed := p.curToken.Token.Literal
	// Escapes are only expanded in double-quoted strings.
	if p.curToken.Token.Offset == 2 {
		Parsed, err = decodeStringEscapes(Parsed)
		if err != nil {
			return nil, errors.WithStack(InvalidEscape(p.curToken, err.Error()))
		}
	}

	return &ast.String{
		Meta:  p.curToken,
		Value: Parsed,
	}, nil
}

func (p *Parser) ParseInteger() (*ast.Integer, error) {
	v, err := strconv.ParseInt(p.curToken.Token.Literal, 10, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "INTEGER"))
	}

	return &ast.Integer{
		Meta:  p.curToken,
		Value: v,
	}, nil
}

func (p *Parser) ParseFloat() (*ast.Float, error) {
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
func (p *Parser) ParseBoolean() *ast.Boolean {
	return &ast.Boolean{
		Meta:  p.curToken,
		Value: p.curToken.Token.Type == token.TRUE,
	}
}

func (p *Parser) ParseRTime() (*ast.RTime, error) {
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
