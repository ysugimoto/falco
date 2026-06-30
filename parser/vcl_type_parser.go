package parser

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/token"
)

func (p *Parser) ParseIdent() *ast.Ident {
	v := &ast.Ident{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}
	v.EndLine = p.curToken.Token.Line
	// To point to the last character, minus 1
	v.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
	return v
}

func (p *Parser) ParseIP() *ast.IP {
	v := &ast.IP{
		Meta:  p.curToken,
		Value: p.curToken.Token.Literal,
	}
	v.EndLine = p.curToken.Token.Line
	// To point to the last character, plus 1 because token is string so add half of offset
	v.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) + (p.curToken.Token.Offset / 2)
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
	str.Token.Position -= len(delimiter)
	str.Token.Position -= 1

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
	str.EndLine = p.curToken.Token.Line
	str.EndPosition = p.curToken.Token.Position

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
	v.EndLine = p.curToken.Token.Line
	v.EndPosition = p.curToken.Token.Position + len(parsed) - 1 + p.curToken.Token.Offset
	return v, nil
}

func (p *Parser) ParseInteger() (*ast.Integer, error) {
	lit := p.curToken.Token.Literal

	// Only the "0x" prefix selects base 16; a leading zero is decimal, not octal.
	base := 10
	digits := lit
	if len(lit) > 2 && lit[0] == '0' && (lit[1] == 'x' || lit[1] == 'X') {
		base = 16
		digits = lit[2:]
	}

	i, err := strconv.ParseInt(digits, base, 64)
	if err != nil {
		// A literal's magnitude must fit signed int64. The sole exception is 2^63
		// (INT_MIN's magnitude), valid only under a unary minus (negating
		// math.MinInt64 wraps back to itself). Larger magnitudes and uint64
		// "masks" overflow and are rejected, matching Fastly.
		negated := p.prevToken != nil && p.prevToken.Token.Type == token.MINUS
		if u, uerr := strconv.ParseUint(digits, base, 64); uerr == nil && u == 1<<63 && negated {
			i = int64(u)
		} else {
			return nil, errors.WithStack(TypeConversionError(p.curToken, "INTEGER"))
		}
	}

	v := &ast.Integer{
		Meta:  p.curToken,
		Value: i,
	}
	v.EndLine = p.curToken.Token.Line
	v.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
	return v, nil
}

func (p *Parser) ParseFloat() (*ast.Float, error) {
	lit := p.curToken.Token.Literal

	// Fastly accepts hex floats without a 'p' exponent (e.g. 0x1.8); Go requires
	// one, so append "p0" to parse (the source literal is preserved).
	parseLit := lit
	isHexFloat := len(lit) > 2 && lit[0] == '0' && (lit[1] == 'x' || lit[1] == 'X')
	if isHexFloat && !strings.Contains(lit, "p") {
		parseLit = lit + "p0"
	}

	f, err := strconv.ParseFloat(parseLit, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "FLOAT"))
	}

	v := &ast.Float{
		Meta:  p.curToken,
		Value: f,
	}
	v.EndLine = p.curToken.Token.Line
	v.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
	return v, nil
}

// nolint: unparam
func (p *Parser) ParseBoolean() *ast.Boolean {
	v := &ast.Boolean{
		Meta:  p.curToken,
		Value: p.curToken.Token.Type == token.TRUE,
	}
	v.EndLine = p.curToken.Token.Line
	v.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
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
	v.EndLine = p.curToken.Token.Line
	v.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1
	return v, nil
}
