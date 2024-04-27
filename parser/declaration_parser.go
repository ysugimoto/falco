package parser

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

func (p *Parser) parseAclDeclaration() (*ast.AclDeclaration, error) {
	acl := &ast.AclDeclaration{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.IDENT))
	}
	acl.Name = p.parseIdent()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.LEFT_BRACE))
	}
	swapLeadingTrailing(p.curToken, acl.Name.Meta)

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		p.nextToken() // point to CIDR start
		cidr, err := p.parseAclCidr()
		if err != nil {
			return nil, errors.WithStack(err)
		} else if cidr != nil {
			acl.CIDRs = append(acl.CIDRs, cidr)
		}
	}
	p.nextToken() // point to RIGHT BRACE

	// RIGHT_BRACE leading comments are ACL infix comments
	swapLeadingInfix(p.curToken, acl.Meta)
	acl.Meta.Trailing = p.trailing()

	return acl, nil
}

func (p *Parser) parseAclCidr() (*ast.AclCidr, error) {
	cidr := &ast.AclCidr{
		Meta: p.curToken,
	}

	// Set inverse if "!" token exists
	var err error
	if p.curTokenIs(token.NOT) {
		cidr.Inverse = &ast.Boolean{
			Meta:  clearComments(p.curToken),
			Value: true,
		}
		p.nextToken() // point to IP token
	}

	if !p.curTokenIs(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.STRING))
	}
	cidr.IP = p.parseIP()
	// If inverse is not set, leading comment should be set as CIDR node leading comment
	if cidr.Inverse == nil {
		cidr.IP.Meta = clearComments(cidr.IP.Meta)
	}

	// If SLASH token is found on peek token, need to parse CIDR mask bit
	if p.peekTokenIs(token.SLASH) {
		p.nextToken() // point to SLASH
		if !p.expectPeek(token.INT) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.INT))
		}

		cidr.Mask, err = p.parseInteger()
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.nextToken() // point to semicolon

	// semicolon leading comment will attach whatever IP or Mask
	if cidr.Mask != nil {
		swapLeadingTrailing(p.curToken, cidr.Mask.Meta)
	} else {
		swapLeadingTrailing(p.curToken, cidr.IP.Meta)
	}
	cidr.Meta.Trailing = p.trailing()

	return cidr, nil
}

func (p *Parser) parseBackendDeclaration() (*ast.BackendDeclaration, error) {
	b := &ast.BackendDeclaration{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	b.Name = p.parseIdent()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	swapLeadingTrailing(p.curToken, b.Name.Meta)

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.parseBackendProperty()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		b.Properties = append(b.Properties, prop)
	}

	if !p.peekTokenIs(token.RIGHT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "RIGHT_BRACE"))
	}

	swapLeadingInfix(p.peekToken, b.Meta)
	p.nextToken()
	b.Meta.Trailing = p.trailing()

	return b, nil
}

func (p *Parser) parseBackendProperty() (*ast.BackendProperty, error) {
	if !p.expectPeek(token.DOT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "DOT"))
	}

	prop := &ast.BackendProperty{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	prop.Key = p.parseIdent()

	if !p.expectPeek(token.ASSIGN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
	}
	swapLeadingTrailing(p.curToken, prop.Key.Meta)
	p.nextToken() // point to right token

	// When current token is "{", property key should be ".probe"
	if p.curTokenIs(token.LEFT_BRACE) {
		probe := &ast.BackendProbeObject{
			Meta: p.curToken,
		}

		for !p.peekTokenIs(token.RIGHT_BRACE) {
			pp, err := p.parseBackendProperty()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			probe.Values = append(probe.Values, pp)
		}

		p.nextToken() // point to RIGHT_BRACE
		swapLeadingInfix(p.curToken, probe.Meta)
		probe.Meta.Trailing = p.trailing()
		prop.Value = probe
		return prop, nil
	}

	// Otherwise, parse expression
	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	prop.Value = exp

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.nextToken() // point to SEMICOLON
	prop.Meta.Trailing = p.trailing()

	return prop, nil
}

func (p *Parser) parseDirectorDeclaration() (*ast.DirectorDeclaration, error) {
	d := &ast.DirectorDeclaration{
		Meta: p.curToken,
	}

	// director name
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	d.Name = p.parseIdent()

	// director type
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	swapLeadingTrailing(p.curToken, d.Name.Meta)

	d.DirectorType = p.parseIdent()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	swapLeadingTrailing(p.curToken, d.DirectorType.Meta)

	// Parse declaration
	for !p.peekTokenIs(token.RIGHT_BRACE) {
		var prop ast.Expression
		var err error

		switch p.peekToken.Token.Type {
		case token.DOT:
			// single property definition like ".quorum = 10%;"
			p.nextToken()
			prop, err = p.parseDirectorProperty()
		case token.LEFT_BRACE:
			p.nextToken()
			// object definition e.g. { .backend = F_origin_1; .weight = 1; }
			prop, err = p.parseDirectorBackend()
		default:
			err = errors.WithStack(UnexpectedToken(p.peekToken))
		}
		if err != nil {
			return nil, errors.WithStack(err)
		}
		d.Properties = append(d.Properties, prop)
	}

	swapLeadingInfix(p.peekToken, d.Meta)
	p.nextToken() // point to RIGHT_BRACE
	d.Meta.Trailing = p.trailing()

	return d, nil
}

func (p *Parser) parseDirectorProperty() (ast.Expression, error) {
	prop := &ast.DirectorProperty{
		Meta: p.curToken,
	}

	// token may token.BACKEND because backend object has ".backend" property key
	if !p.expectPeek(token.IDENT) && !p.expectPeek(token.BACKEND) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	prop.Key = p.parseIdent()

	if !p.expectPeek(token.ASSIGN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
	}
	swapLeadingTrailing(p.curToken, prop.Key.Meta)

	p.nextToken() // point to expression start token

	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	prop.Value = exp

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.nextToken() // point to SEMICOLON
	prop.Meta.Trailing = p.trailing()

	return prop, nil
}

func (p *Parser) parseDirectorBackend() (ast.Expression, error) {
	backend := &ast.DirectorBackendObject{
		Meta: p.curToken,
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		if !p.expectPeek(token.DOT) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "DOT"))
		}

		prop := &ast.DirectorProperty{
			Meta: p.curToken,
		}

		// token may token.BACKEND because backend object has ".backend" property key
		if !p.expectPeek(token.IDENT) && !p.expectPeek(token.BACKEND) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
		}
		prop.Key = p.parseIdent()

		if !p.expectPeek(token.ASSIGN) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
		}
		swapLeadingTrailing(p.curToken, prop.Key.Meta)

		p.nextToken() // point to expression start token

		exp, err := p.parseExpression(LOWEST)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prop.Value = exp

		if !p.peekTokenIs(token.SEMICOLON) {
			return nil, errors.WithStack(MissingSemicolon(p.curToken))
		}
		prop.Meta.Trailing = p.trailing()
		p.nextToken() // point to SEMICOLON

		backend.Values = append(backend.Values, prop)
	}

	swapLeadingInfix(p.peekToken, backend.Meta)
	p.nextToken() // point to RIGHT_BRACE
	backend.Meta.Trailing = p.trailing()

	return backend, nil
}

func (p *Parser) parseTableDeclaration() (*ast.TableDeclaration, error) {
	t := &ast.TableDeclaration{
		Meta:       p.curToken,
		Properties: []*ast.TableProperty{},
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	t.Name = p.parseIdent()
	swapLeadingTrailing(p.peekToken, t.Name.Meta)

	// Table value type is optional
	if p.peekTokenIs(token.IDENT) {
		p.nextToken()
		t.ValueType = p.parseIdent()
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	if t.ValueType != nil {
		swapLeadingTrailing(p.curToken, t.ValueType.Meta)
	} else {
		swapLeadingTrailing(p.curToken, t.Name.Meta)
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.parseTableProperty()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		t.Properties = append(t.Properties, prop)
	}

	swapLeadingInfix(p.peekToken, t.Meta)
	p.nextToken() // point to RIGHT_BRACE
	t.Meta.Trailing = p.trailing()

	return t, nil
}

func (p *Parser) parseTableProperty() (*ast.TableProperty, error) {
	if !p.expectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}
	key, err := p.parseString()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	prop := &ast.TableProperty{
		Meta: p.curToken,
		Key:  key,
	}
	prop.Key.Meta = clearComments(prop.Key.Meta)

	if !p.expectPeek(token.COLON) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COLON"))
	}
	swapLeadingTrailing(p.curToken, prop.Key.Meta)

	p.nextToken() // point to table value token

	switch p.curToken.Token.Type {
	case token.IDENT:
		prop.Value = p.parseIdent()
	case token.STRING:
		var err error
		prop.Value, err = p.parseString()
		if err != nil {
			return nil, errors.WithStack(err)
		}
	case token.ACL, token.BACKEND:
		prop.Value = p.parseIdent()
	case token.TRUE, token.FALSE:
		prop.Value = p.parseBoolean()
	case token.FLOAT:
		if v, err := p.parseFloat(); err != nil {
			return nil, errors.WithStack(err)
		} else {
			prop.Value = v
		}
	case token.INT:
		if v, err := p.parseInteger(); err != nil {
			return nil, errors.WithStack(err)
		} else {
			prop.Value = v
		}
	case token.RTIME:
		if v, err := p.parseRTime(); err != nil {
			return nil, errors.WithStack(err)
		} else {
			prop.Value = v
		}
	default:
		return nil, errors.WithStack(UnexpectedToken(p.curToken))
	}

	// Tailing process: the last table property may not need COLON,
	// so we have to be able to parse these case (COLON exists or not)
	switch p.peekToken.Token.Type {
	case token.COMMA:
		// usual case, user should add trailing comma for east properties :)
		prop.HasComma = true
		p.nextToken() // point to COMMA
		swapLeadingTrailing(p.curToken, prop.Value.GetMeta())
		prop.Meta.Trailing = p.trailing()
	case token.RIGHT_BRACE:
		// if peed token is RIGHT_BRACE, it means table declaration end. if also be valid
		// Note that in this case, we could not parse trailing comment. it is parsed as declaration infix comment.
		prop.Meta.Trailing = p.trailing()

		// DO NOT advance token!

	default:
		// Other tokens are invalid
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
	}

	return prop, nil
}

func (p *Parser) parseSubroutineDeclaration() (*ast.SubroutineDeclaration, error) {
	s := &ast.SubroutineDeclaration{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	s.Name = p.parseIdent()

	// Custom subroutines might be returning a type
	// https://developer.fastly.com/reference/vcl/subroutines/
	// we dont need to validate the type here, linter will do that later.
	if p.expectPeek(token.IDENT) {
		s.ReturnType = p.parseIdent()
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	var err error
	if s.Block, err = p.parseBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}
	// After block statement is parsed, cursor should point to RIGHT_BRACE, end of block statement

	return s, nil
}

func (p *Parser) parsePenaltyboxDeclaration() (*ast.PenaltyboxDeclaration, error) {
	pb := &ast.PenaltyboxDeclaration{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	pb.Name = p.parseIdent()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	var err error
	if pb.Block, err = p.parseBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}

	return pb, nil
}

func (p *Parser) parseRatecounterDeclaration() (*ast.RatecounterDeclaration, error) {
	r := &ast.RatecounterDeclaration{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	r.Name = p.parseIdent()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	var err error
	if r.Block, err = p.parseBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}

	return r, nil
}
