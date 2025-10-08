package parser

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

func (p *Parser) ParseIdent() *ast.Ident {
	v := &ast.Ident{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}
	v.Meta.EndLine = p.curToken.Token.Line
	// To point to the last character, minus 1
	v.Meta.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
	return v
}

func (p *Parser) ParseIP() *ast.IP {
	v := &ast.IP{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}
	v.Meta.EndLine = p.curToken.Token.Line
	// To point to the last character, plus 1 because token is string so add half of offset
	v.Meta.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) + (p.curToken.Token.Offset / 2)
	return v
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
	str.Meta.Token.Position -= len(delimiter)
	str.Meta.Token.Position -= 1

	if !p.PeekTokenIs(token.CLOSE_LONG_STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.CLOSE_LONG_STRING))
	}
	// Check open and close delimiter string is the same
	if delimiter != p.peekToken.Token.Literal {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.CLOSE_LONG_STRING))
	}

	str.GetMeta().Leading = openToken.Leading
	str.GetMeta().Trailing = p.peekToken.Trailing
	p.NextToken() // point to end delimiter
	str.Meta.EndLine = p.curToken.Token.Line
	str.Meta.EndPosition = p.curToken.Token.Position

	return str, err
}

func (p *Parser) ParseString() (*ast.String, error) {
	var err error
	parsed := p.curToken.Token.Literal
	// Escapes are only expanded in double-quoted strings.
	if p.curToken.Token.Offset == 2 {
		parsed, err = decodeStringEscapes(parsed)
		if err != nil {
			return nil, errors.WithStack(InvalidEscape(p.curToken, err.Error()))
		}
	}

	v := &ast.String{
		Meta:  p.curToken,
		Value: parsed,
	}
	v.Meta.EndLine = p.curToken.Token.Line
	v.Meta.EndPosition = p.curToken.Token.Position + len(parsed) - 1 + p.curToken.Token.Offset
	return v, nil
}

func (p *Parser) ParseInteger() (*ast.Integer, error) {
	i, err := strconv.ParseInt(p.curToken.Token.Literal, 10, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "INTEGER"))
	}

	v := &ast.Integer{
		Meta:  p.curToken,
		Value: i,
	}
	v.Meta.EndLine = p.curToken.Token.Line
	v.Meta.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
	return v, nil
}

func (p *Parser) ParseFloat() (*ast.Float, error) {
	f, err := strconv.ParseFloat(p.curToken.Token.Literal, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "FLOAT"))
	}

	v := &ast.Float{
		Meta:  p.curToken,
		Value: f,
	}
	v.Meta.EndLine = p.curToken.Token.Line
	v.Meta.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
	return v, nil
}

// nolint: unparam
func (p *Parser) ParseBoolean() *ast.Boolean {
	v := &ast.Boolean{
		Meta:  p.curToken,
		Value: p.curToken.Token.Type == token.TRUE,
	}
	v.Meta.EndLine = p.curToken.Token.Line
	v.Meta.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
	return v
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
	v := &ast.RTime{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}
	v.Meta.EndLine = p.curToken.Token.Line
	v.Meta.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
	return v, nil
}
