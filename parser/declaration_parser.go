package parser

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

func (p *Parser) ParseAclDeclaration() (*ast.AclDeclaration, error) {
	acl := &ast.AclDeclaration{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.IDENT))
	}
	acl.Name = p.ParseIdent()

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.LEFT_BRACE))
	}
	SwapLeadingTrailing(p.curToken, acl.Name.Meta)

	for !p.PeekTokenIs(token.RIGHT_BRACE) {
		p.NextToken() // point to CIDR start
		cidr, err := p.ParseAclCidr()
		if err != nil {
			return nil, errors.WithStack(err)
		} else if cidr != nil {
			acl.CIDRs = append(acl.CIDRs, cidr)
		}
	}
	p.NextToken() // point to RIGHT BRACE

	// RIGHT_BRACE leading comments are ACL infix comments
	SwapLeadingInfix(p.curToken, acl.Meta)
	acl.Meta.Trailing = p.Trailing()
	acl.Meta.EndLine = p.curToken.Token.Line
	acl.Meta.EndPosition = p.curToken.Token.Position

	return acl, nil
}

func (p *Parser) ParseAclCidr() (*ast.AclCidr, error) {
	cidr := &ast.AclCidr{
		Meta: p.curToken,
	}

	// Set inverse if "!" token exists
	var err error
	if p.CurTokenIs(token.NOT) {
		cidr.Inverse = &ast.Boolean{
			Meta:  clearComments(p.curToken),
			Value: true,
		}
		p.NextToken() // point to IP token
	}

	if !p.CurTokenIs(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.STRING))
	}
	cidr.IP = p.ParseIP()
	// If inverse is not set, leading comment should be set as CIDR node leading comment
	if cidr.Inverse == nil {
		cidr.IP.Meta = clearComments(cidr.IP.Meta)
	}

	endPosition := cidr.IP.EndPosition
	// If SLASH token is found on peek token, need to Parse CIDR mask bit
	if p.PeekTokenIs(token.SLASH) {
		p.NextToken() // point to SLASH
		if !p.ExpectPeek(token.INT) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.INT))
		}

		cidr.Mask, err = p.ParseInteger()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		endPosition = cidr.Mask.EndPosition
	}

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	cidr.Meta.EndLine = p.curToken.Token.Line
	cidr.Meta.EndPosition = endPosition
	p.NextToken() // point to semicolon

	// semicolon leading comment will attach whatever IP or Mask
	if cidr.Mask != nil {
		SwapLeadingTrailing(p.curToken, cidr.Mask.Meta)
	} else {
		SwapLeadingTrailing(p.curToken, cidr.IP.Meta)
	}
	cidr.Meta.Trailing = p.Trailing()

	return cidr, nil
}

func (p *Parser) ParseBackendDeclaration() (*ast.BackendDeclaration, error) {
	b := &ast.BackendDeclaration{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	b.Name = p.ParseIdent()

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	SwapLeadingTrailing(p.curToken, b.Name.Meta)

	for !p.PeekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.ParseBackendProperty()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		b.Properties = append(b.Properties, prop)
	}

	if !p.PeekTokenIs(token.RIGHT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "RIGHT_BRACE"))
	}

	SwapLeadingInfix(p.peekToken, b.Meta)
	p.NextToken() // point to RIGHT_BRACE
	b.Meta.Trailing = p.Trailing()
	b.Meta.EndLine = p.curToken.Token.Line
	b.Meta.EndPosition = p.curToken.Token.Position

	return b, nil
}

func (p *Parser) ParseBackendProperty() (*ast.BackendProperty, error) {
	if !p.ExpectPeek(token.DOT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "DOT"))
	}

	prop := &ast.BackendProperty{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	prop.Key = p.ParseIdent()

	if !p.ExpectPeek(token.ASSIGN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
	}
	SwapLeadingTrailing(p.curToken, prop.Key.Meta)
	p.NextToken() // point to right token

	// When current token is "{", property key should be ".probe"
	if p.CurTokenIs(token.LEFT_BRACE) {
		probe := &ast.BackendProbeObject{
			Meta: p.curToken,
		}

		for !p.PeekTokenIs(token.RIGHT_BRACE) {
			pp, err := p.ParseBackendProperty()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			probe.Values = append(probe.Values, pp)
		}

		p.NextToken() // point to RIGHT_BRACE
		SwapLeadingInfix(p.curToken, probe.Meta)
		probe.Meta.Trailing = p.Trailing()
		prop.Value = probe
		probe.Meta.EndLine = p.curToken.Token.Line
		probe.Meta.EndPosition = p.curToken.Token.Position
		prop.Meta.EndLine = p.curToken.Token.Line
		prop.Meta.EndPosition = p.curToken.Token.Position
		return prop, nil
	}

	// Otherwise, Parse expression
	exp, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	prop.Value = exp

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	prop.Meta.EndLine = prop.Value.GetMeta().EndLine
	prop.Meta.EndPosition = prop.Value.GetMeta().EndPosition
	p.NextToken() // point to SEMICOLON
	prop.Meta.Trailing = p.Trailing()

	return prop, nil
}

func (p *Parser) ParseDirectorDeclaration() (*ast.DirectorDeclaration, error) {
	d := &ast.DirectorDeclaration{
		Meta: p.curToken,
	}

	// director name
	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	d.Name = p.ParseIdent()

	// director type
	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	SwapLeadingTrailing(p.curToken, d.Name.Meta)

	d.DirectorType = p.ParseIdent()

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	SwapLeadingTrailing(p.curToken, d.DirectorType.Meta)

	// Parse declaration
	for !p.PeekTokenIs(token.RIGHT_BRACE) {
		var prop ast.Expression
		var err error

		switch p.peekToken.Token.Type {
		case token.DOT:
			// single property definition like ".quorum = 10%;"
			p.NextToken()
			prop, err = p.ParseDirectorProperty()
		case token.LEFT_BRACE:
			p.NextToken()
			// object definition e.g. { .backend = F_origin_1; .weight = 1; }
			prop, err = p.ParseDirectorBackend()
		default:
			err = errors.WithStack(UnexpectedToken(p.peekToken))
		}
		if err != nil {
			return nil, errors.WithStack(err)
		}
		d.Properties = append(d.Properties, prop)
	}

	SwapLeadingInfix(p.peekToken, d.Meta)
	p.NextToken() // point to RIGHT_BRACE
	d.Meta.Trailing = p.Trailing()
	d.Meta.EndLine = p.curToken.Token.Line
	d.Meta.EndPosition = p.curToken.Token.Position

	return d, nil
}

func (p *Parser) ParseDirectorProperty() (ast.Expression, error) {
	prop := &ast.DirectorProperty{
		Meta: p.curToken,
	}

	// token may token.BACKEND because backend object has ".backend" property key
	if !p.ExpectPeek(token.IDENT) && !p.ExpectPeek(token.BACKEND) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	prop.Key = p.ParseIdent()

	if !p.ExpectPeek(token.ASSIGN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
	}
	SwapLeadingTrailing(p.curToken, prop.Key.Meta)

	p.NextToken() // point to expression start token

	exp, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	prop.Value = exp

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	prop.Meta.EndLine = exp.GetMeta().EndLine
	prop.Meta.EndPosition = exp.GetMeta().EndPosition
	p.NextToken() // point to SEMICOLON
	prop.Meta.Trailing = p.Trailing()

	return prop, nil
}

func (p *Parser) ParseDirectorBackend() (ast.Expression, error) {
	backend := &ast.DirectorBackendObject{
		Meta: p.curToken,
	}

	for !p.PeekTokenIs(token.RIGHT_BRACE) {
		if !p.ExpectPeek(token.DOT) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "DOT"))
		}

		prop := &ast.DirectorProperty{
			Meta: p.curToken,
		}

		// token may token.BACKEND because backend object has ".backend" property key
		if !p.ExpectPeek(token.IDENT) && !p.ExpectPeek(token.BACKEND) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
		}
		prop.Key = p.ParseIdent()

		if !p.ExpectPeek(token.ASSIGN) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
		}
		SwapLeadingTrailing(p.curToken, prop.Key.Meta)

		p.NextToken() // point to expression start token

		exp, err := p.ParseExpression(LOWEST)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prop.Value = exp

		if !p.PeekTokenIs(token.SEMICOLON) {
			return nil, errors.WithStack(MissingSemicolon(p.curToken))
		}
		prop.Meta.EndLine = exp.GetMeta().EndLine
		prop.Meta.EndPosition = exp.GetMeta().EndPosition
		prop.Meta.Trailing = p.Trailing()
		p.NextToken() // point to SEMICOLON

		backend.Values = append(backend.Values, prop)
	}

	SwapLeadingInfix(p.peekToken, backend.Meta)
	p.NextToken() // point to RIGHT_BRACE
	backend.Meta.Trailing = p.Trailing()
	backend.Meta.EndLine = p.curToken.Token.Line
	backend.Meta.EndPosition = p.curToken.Token.Position

	return backend, nil
}

func (p *Parser) ParseTableDeclaration() (*ast.TableDeclaration, error) {
	t := &ast.TableDeclaration{
		Meta:       p.curToken,
		Properties: []*ast.TableProperty{},
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	t.Name = p.ParseIdent()
	SwapLeadingTrailing(p.peekToken, t.Name.Meta)

	// Table value type is optional
	if p.PeekTokenIs(token.IDENT) {
		p.NextToken()
		t.ValueType = p.ParseIdent()
	}

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	if t.ValueType != nil {
		SwapLeadingTrailing(p.curToken, t.ValueType.Meta)
	} else {
		SwapLeadingTrailing(p.curToken, t.Name.Meta)
	}

	for !p.PeekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.ParseTableProperty()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		t.Properties = append(t.Properties, prop)
	}

	SwapLeadingInfix(p.peekToken, t.Meta)
	p.NextToken() // point to RIGHT_BRACE
	t.Meta.Trailing = p.Trailing()
	t.Meta.EndLine = p.curToken.Token.Line
	t.Meta.EndPosition = p.curToken.Token.Position

	return t, nil
}

func (p *Parser) ParseTableProperty() (*ast.TableProperty, error) {
	if !p.ExpectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}
	key, err := p.ParseString()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	prop := &ast.TableProperty{
		Meta: p.curToken,
		Key:  key,
	}
	prop.Key.Meta = clearComments(prop.Key.Meta)

	if !p.ExpectPeek(token.COLON) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COLON"))
	}
	SwapLeadingTrailing(p.curToken, prop.Key.Meta)

	p.NextToken() // point to table value token

	switch p.curToken.Token.Type {
	case token.IDENT:
		prop.Value = p.ParseIdent()
	case token.STRING:
		var err error
		prop.Value, err = p.ParseString()
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case token.ACL, token.BACKEND:
		prop.Value = p.ParseIdent()
	case token.TRUE, token.FALSE:
		prop.Value = p.ParseBoolean()
	case token.FLOAT:
		if v, err := p.ParseFloat(); err != nil {
			return nil, errors.WithStack(err)
		} else {
			prop.Value = v
		}
	case token.INT:
		if v, err := p.ParseInteger(); err != nil {
			return nil, errors.WithStack(err)
		} else {
			prop.Value = v
		}
	case token.RTIME:
		if v, err := p.ParseRTime(); err != nil {
			return nil, errors.WithStack(err)
		} else {
			prop.Value = v
		}
	default:
		return nil, errors.WithStack(UnexpectedToken(p.curToken))
	}

	// Tailing process: the last table property may not need COLON,
	// so we have to be able to Parse these case (COLON exists or not)
	switch p.peekToken.Token.Type {
	case token.COMMA:
		// usual case, user should add Trailing comma for east properties :)
		prop.HasComma = true
		prop.Meta.EndLine = prop.Value.GetMeta().EndLine
		prop.Meta.EndPosition = prop.Value.GetMeta().EndPosition

		p.NextToken() // point to COMMA
		SwapLeadingTrailing(p.curToken, prop.Value.GetMeta())
		prop.Meta.Trailing = p.Trailing()
	case token.RIGHT_BRACE:
		// if peed token is RIGHT_BRACE, it means table declaration end. if also be valid
		// Note that in this case, we could not Parse Trailing comment. it is Parsed as declaration infix comment.
		prop.Meta.Trailing = p.Trailing()

		prop.Meta.EndLine = prop.Value.GetMeta().EndLine
		prop.Meta.EndPosition = prop.Value.GetMeta().EndPosition

		// DO NOT advance token!

	default:
		// Other tokens are invalid
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
	}

	return prop, nil
}

func (p *Parser) ParseSubroutineDeclaration() (*ast.SubroutineDeclaration, error) {
	s := &ast.SubroutineDeclaration{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	s.Name = p.ParseIdent()

	// Custom subroutines might be returning a type
	// https://developer.fastly.com/reference/vcl/subroutines/
	// we dont need to validate the type here, linter will do that later.
	if p.ExpectPeek(token.IDENT) {
		SwapLeadingTrailing(p.curToken, s.Name.Meta)
		s.ReturnType = p.ParseIdent()
	}

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	if s.ReturnType != nil {
		SwapLeadingTrailing(p.curToken, s.ReturnType.Meta)
	} else {
		SwapLeadingTrailing(p.curToken, s.Name.Meta)
	}

	var err error
	if s.Block, err = p.ParseBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}
	s.Meta.EndLine = p.curToken.Token.Line
	s.Meta.EndPosition = p.curToken.Token.Position
	// After block statement is Parsed, cursor should point to RIGHT_BRACE, end of block statement

	return s, nil
}

func (p *Parser) ParsePenaltyboxDeclaration() (*ast.PenaltyboxDeclaration, error) {
	pb := &ast.PenaltyboxDeclaration{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	pb.Name = p.ParseIdent()

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	SwapLeadingTrailing(p.curToken, pb.Name.Meta)

	var err error
	if pb.Block, err = p.ParseBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}
	pb.Meta.EndLine = p.curToken.Token.Line
	pb.Meta.EndPosition = p.curToken.Token.Position

	return pb, nil
}

func (p *Parser) ParseRatecounterDeclaration() (*ast.RatecounterDeclaration, error) {
	r := &ast.RatecounterDeclaration{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	r.Name = p.ParseIdent()

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	SwapLeadingTrailing(p.curToken, r.Name.Meta)

	var err error
	if r.Block, err = p.ParseBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}
	r.Meta.EndLine = p.curToken.Token.Line
	r.Meta.EndPosition = p.curToken.Token.Position

	return r, nil
}
