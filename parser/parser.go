package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/token"
)

const (
	LOWEST int = iota + 1
	AND
	OR
	REGEX
	EQUALS
	LESS_GREATER
	CONCAT
	PREFIX
	CALL
)

var precedences = map[token.TokenType]int{
	token.EQUAL:              EQUALS,
	token.NOT_EQUAL:          EQUALS,
	token.GREATER_THAN:       LESS_GREATER,
	token.GREATER_THAN_EQUAL: LESS_GREATER,
	token.LESS_THAN:          LESS_GREATER,
	token.LESS_THAN_EQUAL:    LESS_GREATER,
	token.REGEX_MATCH:        REGEX,
	token.NOT_REGEX_MATCH:    REGEX,
	token.PLUS:               CONCAT,
	token.STRING:             CONCAT,
	token.IDENT:              CONCAT,
	token.IF:                 CONCAT,
	token.LEFT_PAREN:         CALL,
	token.AND:                AND,
	token.OR:                 OR,
}

type (
	prefixParser func() (ast.Expression, error)
	infixParser  func(ast.Expression) (ast.Expression, error)
)

type Parser struct {
	l *lexer.Lexer

	prevToken token.Token
	curToken  token.Token
	peekToken token.Token
	stack     ast.Comments

	prefixParsers map[token.TokenType]prefixParser
	infixParsers  map[token.TokenType]infixParser
}

func New(l *lexer.Lexer) *Parser {
	p := &Parser{
		l: l,
	}

	p.prefixParsers = map[token.TokenType]prefixParser{
		token.IDENT:      func() (ast.Expression, error) { return p.parseIdent(), nil },
		token.STRING:     func() (ast.Expression, error) { return p.parseString(), nil },
		token.INT:        func() (ast.Expression, error) { return p.parseInteger() },
		token.FLOAT:      func() (ast.Expression, error) { return p.parseFloat() },
		token.RTIME:      func() (ast.Expression, error) { return p.parseRTime() },
		token.NOT:        func() (ast.Expression, error) { return p.parsePrefixExpression() },
		token.MINUS:      func() (ast.Expression, error) { return p.parsePrefixExpression() },
		token.PLUS:       func() (ast.Expression, error) { return p.parsePrefixExpression() },
		token.TRUE:       func() (ast.Expression, error) { return p.parseBoolean(), nil },
		token.FALSE:      func() (ast.Expression, error) { return p.parseBoolean(), nil },
		token.LEFT_PAREN: func() (ast.Expression, error) { return p.parseGroupedExpression() },
		token.IF:         func() (ast.Expression, error) { return p.parseIfExpression() },
	}
	p.infixParsers = map[token.TokenType]infixParser{
		token.IF:                 p.parseInfixStringConcatExpression,
		token.PLUS:               p.parseInfixStringConcatExpression,
		token.STRING:             p.parseInfixStringConcatExpression,
		token.IDENT:              p.parseInfixStringConcatExpression,
		token.MINUS:              p.parseInfixExpression,
		token.EQUAL:              p.parseInfixExpression,
		token.NOT_EQUAL:          p.parseInfixExpression,
		token.GREATER_THAN:       p.parseInfixExpression,
		token.GREATER_THAN_EQUAL: p.parseInfixExpression,
		token.LESS_THAN:          p.parseInfixExpression,
		token.LESS_THAN_EQUAL:    p.parseInfixExpression,
		token.REGEX_MATCH:        p.parseInfixExpression,
		token.NOT_REGEX_MATCH:    p.parseInfixExpression,
		token.LEFT_PAREN:         p.parseFunctionCallExpression,
		token.AND:                p.parseInfixExpression,
		token.OR:                 p.parseInfixExpression,
	}

	p.nextToken()
	p.nextToken()

	return p
}

func (p *Parser) nextToken() {
	p.prevToken = p.curToken
	p.curToken = p.peekToken
	for {
		t := p.l.NextToken()
		if t.Type == token.LF {
			continue
		} else if t.Type == token.COMMENT {
			p.stack = append(p.stack, &ast.Comment{
				Token: t,
				Value: t.Literal,
			})
			continue
		}
		p.peekToken = t
		break
	}
}

func (p *Parser) comments() ast.Comments {
	c := append(ast.Comments{}, p.stack...)
	p.stack = ast.Comments{}
	return c
}

func (p *Parser) curTokenIs(t token.TokenType) bool {
	return p.curToken.Type == t
}

func (p *Parser) peekTokenIs(t token.TokenType) bool {
	return p.peekToken.Type == t
}

func (p *Parser) expectPeek(t token.TokenType) bool {
	if !p.peekTokenIs(t) {
		return false
	}
	p.nextToken()
	return true
}

func (p *Parser) expectTrail(t token.TokenType) (ast.Comments, bool) {
	if !p.peekTokenIs(t) {
		return nil, false
	}
	c := ast.Comments{}
	for {
		tok := p.l.NextToken()
		if tok.Type == token.LF || tok.Type == token.EOF {
			break
		}
		if tok.Type == token.COMMENT {
			c = append(c, &ast.Comment{
				Token: tok,
				Value: tok.Literal,
			})
			continue
		}
		break
	}
	p.nextToken()
	return c, true
}

func (p *Parser) curPrecedence() int {
	if v, ok := precedences[p.curToken.Type]; ok {
		return v
	}
	return LOWEST
}

func (p *Parser) peekPrecedence() int {
	if v, ok := precedences[p.peekToken.Type]; ok {
		return v
	}
	return LOWEST
}

func (p *Parser) ParseVCL() (*ast.VCL, error) {
	vcl := &ast.VCL{}

	for !p.curTokenIs(token.EOF) {
		stmt, err := p.parseDeclaration()
		if err != nil {
			return nil, err
		} else if stmt != nil {
			vcl.Statements = append(vcl.Statements, stmt)
		}
	}

	return vcl, nil
}

func (p *Parser) parseDeclaration() (ast.Statement, error) {
	var stmt ast.Statement
	var err error

	switch p.curToken.Type {
	case token.ACL:
		stmt, err = p.parseAclDeclaration()
	case token.IMPORT:
		stmt, err = p.parseImportStatement()
	case token.INCLUDE:
		stmt, err = p.parseIncludeStatement()
	case token.BACKEND:
		stmt, err = p.parseBackendDeclaration()
	case token.DIRECTOR:
		stmt, err = p.parseDirectorDeclaration()
	case token.TABLE:
		stmt, err = p.parseTableDeclaration()
	case token.SUBROUTINE:
		stmt, err = p.parseSubroutineDeclaration()
	default:
		err = UnexpectedToken(p.curToken)
	}

	if err != nil {
		return nil, errors.WithStack(err)
	}
	p.nextToken()
	return stmt, nil
}

func (p *Parser) parseAclDeclaration() (*ast.AclDeclaration, error) {
	acl := &ast.AclDeclaration{
		Meta: ast.New(p.curToken, 0, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.IDENT))
	}
	acl.Name = p.parseIdent()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.LEFT_BRACE))
	}
	acl.Name.Meta.Trailing = p.comments()

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		p.nextToken()
		cidr, err := p.parseAclCidr()
		if err != nil {
			return nil, errors.WithStack(err)
		} else if cidr != nil {
			acl.CIDRs = append(acl.CIDRs, cidr)
		}
	}
	acl.Meta.Infix = p.comments()
	if c, ok := p.expectTrail(token.RIGHT_BRACE); !ok {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "RIGHT_BRACE"))
	} else {
		acl.Meta.Trailing = c
	}
	return acl, nil
}

func (p *Parser) parseAclCidr() (*ast.AclCidr, error) {
	cidr := &ast.AclCidr{
		Meta: ast.New(p.curToken, 1, p.comments()),
	}
	// Set inverse if "!" token exists
	var err error
	if p.curTokenIs(token.NOT) {
		cidr.Inverse = &ast.Boolean{
			Meta:  ast.New(p.curToken, 0, p.comments()),
			Value: true,
		}
		p.nextToken()
	}

	if !p.curTokenIs(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.STRING))
	}
	cidr.IP = p.parseIP()

	// Add mask token if found in "/" on next token
	if p.peekTokenIs(token.SLASH) {
		p.nextToken()
		if !p.expectPeek(token.INT) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.INT))
		}

		cidr.Mask, err = p.parseInteger()
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	} else {
		cidr.Meta.Trailing = c
	}

	return cidr, nil
}

func (p *Parser) parseImportStatement() (*ast.ImportStatement, error) {
	i := &ast.ImportStatement{
		Meta: ast.New(p.curToken, 0, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	i.Name = p.parseIdent()

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	} else {
		i.Meta.Trailing = c
	}

	return i, nil
}

func (p *Parser) parseIncludeStatement() (ast.Statement, error) {
	i := &ast.IncludeStatement{
		Meta: ast.New(p.curToken, 0, p.comments()),
	}

	if !p.expectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}
	i.Module = p.parseString()

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	} else {
		i.Meta.Trailing = c
	}

	return i, nil
}

func (p *Parser) parseBackendDeclaration() (*ast.BackendDeclaration, error) {
	b := &ast.BackendDeclaration{
		Meta: ast.New(p.curToken, 0, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	b.Name = p.parseIdent()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.parseBackendProperty(1)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		b.Properties = append(b.Properties, prop)
	}

	if c, ok := p.expectTrail(token.RIGHT_BRACE); !ok {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "RIGHT_BRACE"))
	} else {
		b.Meta.Trailing = c
	}
	return b, nil
}

func (p *Parser) parseBackendProperty(nestLevel int) (*ast.BackendProperty, error) {
	if !p.expectPeek(token.DOT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "DOT"))
	}

	prop := &ast.BackendProperty{
		Meta: ast.New(p.curToken, nestLevel, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	prop.Key = p.parseIdent()

	if !p.expectPeek(token.ASSIGN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
	}
	prop.Key.Meta.Trailing = p.comments()

	p.nextToken() // point to right token

	// When current token is "{", property key should be ".probe"
	if p.curTokenIs(token.LEFT_BRACE) {
		probe := &ast.BackendProbeObject{
			Meta: ast.New(p.curToken, nestLevel),
		}

		for !p.peekTokenIs(token.RIGHT_BRACE) {
			pp, err := p.parseBackendProperty(nestLevel + 1)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			probe.Values = append(probe.Values, pp)
		}

		if c, ok := p.expectTrail(token.RIGHT_BRACE); !ok {
			return nil, errors.WithStack(UnexpectedToken(p.curToken, "RIGHT_BRACE"))
		} else {
			probe.Meta.Trailing = c
		}
		prop.Value = probe
		return prop, nil
	}

	// Otherwise, parse expression
	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	prop.Value = exp

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	} else {
		prop.Meta.Trailing = c
	}

	return prop, nil
}

func (p *Parser) parseDirectorDeclaration() (*ast.DirectorDeclaration, error) {
	d := &ast.DirectorDeclaration{
		Meta: ast.New(p.curToken, 0, p.comments()),
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
	d.DirectorType = p.parseIdent()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		var prop ast.Expression
		var err error

		switch p.peekToken.Type {
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
	d.Meta.Infix = p.comments()

	if c, ok := p.expectTrail(token.RIGHT_BRACE); !ok {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "RIGHT_BRACE"))
	} else {
		d.Meta.Trailing = c
	}
	return d, nil
}

func (p *Parser) parseDirectorProperty() (ast.Expression, error) {
	prop := &ast.DirectorProperty{
		Meta: ast.New(p.curToken, 1, p.comments()),
	}

	// token may token.BACKEND because backend object has ".backend" property key
	if !p.expectPeek(token.IDENT) && !p.expectPeek(token.BACKEND) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	prop.Key = p.parseIdent()

	if !p.expectPeek(token.ASSIGN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
	}
	prop.Key.Meta.Trailing = p.comments()

	p.nextToken() // point to expression start token

	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	prop.Value = exp

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	} else {
		prop.Meta.Trailing = c
	}
	return prop, nil
}

func (p *Parser) parseDirectorBackend() (ast.Expression, error) {
	prop := &ast.DirectorBackendObject{
		Meta: ast.New(p.curToken, 1, p.comments()),
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		if !p.expectPeek(token.DOT) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "DOT"))
		}

		subProp := &ast.DirectorProperty{
			Meta: ast.New(p.curToken, 1, p.comments()),
		}

		// token may token.BACKEND because backend object has ".backend" property key
		if !p.expectPeek(token.IDENT) && !p.expectPeek(token.BACKEND) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
		}
		subProp.Key = p.parseIdent()

		if !p.expectPeek(token.ASSIGN) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
		}
		subProp.Key.Meta.Trailing = p.comments()

		p.nextToken() // point to expression start token

		exp, err := p.parseExpression(LOWEST)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		subProp.Value = exp
		if !p.expectPeek(token.SEMICOLON) {
			return nil, errors.WithStack(MissingSemicolon(p.curToken))
		}
		subProp.Meta.Trailing = p.comments()
		prop.Values = append(prop.Values, subProp)
	}

	if c, ok := p.expectTrail(token.RIGHT_BRACE); !ok {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "RIGHT_BRACE"))
	} else {
		prop.Meta.Trailing = c
	}
	return prop, nil
}

func (p *Parser) parseTableDeclaration() (*ast.TableDeclaration, error) {
	t := &ast.TableDeclaration{
		Meta: ast.New(p.curToken, 0, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	t.Name = p.parseIdent()

	// Table value type is optional
	if p.peekTokenIs(token.IDENT) {
		p.nextToken()
		t.ValueType = p.parseIdent()
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	if t.ValueType != nil {
		t.ValueType.Meta.Trailing = p.comments()
	} else {
		t.Name.Meta.Trailing = p.comments()
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.parseTableProperty()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		t.Properties = append(t.Properties, prop)
	}

	if c, ok := p.expectTrail(token.RIGHT_BRACE); !ok {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "RIGHT_BRACE"))
	} else {
		t.Meta.Trailing = c
	}
	return t, nil
}

func (p *Parser) parseTableProperty() (*ast.TableProperty, error) {
	prop := &ast.TableProperty{
		Meta: ast.New(p.curToken, 1, p.comments()),
	}

	if !p.expectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}
	prop.Key = p.parseString()

	if !p.expectPeek(token.COLON) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COLON"))
	}

	switch p.peekToken.Type {
	case token.STRING:
		p.nextToken()
		prop.Value = p.parseString()
	case token.ACL, token.BACKEND:
		p.nextToken()
		prop.Value = p.parseIdent()
	case token.TRUE, token.FALSE:
		p.nextToken()
		prop.Value = p.parseBoolean()
	case token.FLOAT:
		p.nextToken()
		if v, err := p.parseFloat(); err != nil {
			return nil, errors.WithStack(err)
		} else {
			prop.Value = v
		}
	case token.INT:
		p.nextToken()
		if v, err := p.parseInteger(); err != nil {
			return nil, errors.WithStack(err)
		} else {
			prop.Value = v
		}
	case token.RTIME:
		p.nextToken()
		if v, err := p.parseRTime(); err != nil {
			return nil, errors.WithStack(err)
		} else {
			prop.Value = v
		}
	default:
		return nil, errors.WithStack(UnexpectedToken(p.peekToken))
	}

	if p.peekTokenIs(token.COMMA) {
		if c, ok := p.expectTrail(token.COMMA); ok {
			prop.Meta.Trailing = c
		}
	} else if p.peekTokenIs(token.RIGHT_BRACE) {
		prop.Meta.Trailing = p.comments()
	} else {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "COMMA"))
	}
	return prop, nil
}

func (p *Parser) parseSubroutineDeclaration() (*ast.SubroutineDeclaration, error) {
	s := &ast.SubroutineDeclaration{
		Meta: ast.New(p.curToken, 0, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	s.Name = p.parseIdent()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	var err error
	if s.Block, err = p.parseBlockStatement(1); err != nil {
		return nil, errors.WithStack(err)
	}

	if c, ok := p.expectTrail(token.RIGHT_BRACE); !ok {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "COMMA"))
	} else {
		s.Meta.Trailing = c
	}

	return s, nil
}

func (p *Parser) parseBlockStatement(nest int) (*ast.BlockStatement, error) {
	b := &ast.BlockStatement{
		Meta:       ast.New(p.curToken, nest),
		Statements: []ast.Statement{},
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		var stmt ast.Statement
		var err error

		switch p.peekToken.Type {
		case token.SET:
			stmt, err = p.parseSetStatement(nest)
		case token.UNSET:
			p.nextToken()
			stmt, err = p.parseUnsetStatement(nest)
		case token.REMOVE:
			p.nextToken()
			stmt, err = p.parseRemoveStatement(nest)
		case token.ADD:
			p.nextToken()
			stmt, err = p.parseAddStatement(nest)
		case token.CALL:
			p.nextToken()
			stmt, err = p.parseCallStatement(nest)
		case token.DECLARE:
			p.nextToken()
			stmt, err = p.parseDeclareStatement(nest)
		case token.ERROR:
			p.nextToken()
			stmt, err = p.parseErrorStatement(nest)
		case token.ESI:
			p.nextToken()
			stmt, err = p.parseEsiStatement(nest)
		case token.LOG:
			p.nextToken()
			stmt, err = p.parseLogStatement(nest)
		case token.RESTART:
			p.nextToken()
			stmt, err = p.parseRestartStatement(nest)
		case token.RETURN:
			p.nextToken()
			stmt, err = p.parseReturnStatement(nest)
		case token.SYNTHETIC:
			p.nextToken()
			stmt, err = p.parseSyntheticStatement(nest)
		case token.SYNTHETIC_BASE64:
			p.nextToken()
			stmt, err = p.parseSyntheticBase64Statement(nest)
		case token.IF:
			stmt, err = p.parseIfStatement(nest)
		default:
			err = UnexpectedToken(p.peekToken)
		}
		if err != nil {
			return nil, errors.WithStack(err)
		}
		b.Statements = append(b.Statements, stmt)
	}

	b.Meta.Trailing = p.comments()
	return b, nil
}

// nolint: dupl
func (p *Parser) parseSetStatement(nest int) (*ast.SetStatement, error) {
	stmt := &ast.SetStatement{
		Meta: ast.New(p.peekToken, nest, p.comments()),
	}
	p.nextToken()

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.parseIdent()
	stmt.Ident.Meta.Leading = p.comments()

	if !isAssignmentOperator(p.peekToken) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, assignmentOperatorLiterals...))
	}
	p.nextToken() // point to assignment operator

	stmt.Operator = &ast.Operator{
		Token:    p.curToken,
		Operator: p.curToken.Literal,
	}
	p.nextToken() // point to right expression start

	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = exp

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

func (p *Parser) parseExpression(precedence int) (ast.Expression, error) {
	// Note: trim comment inside expression list
	// For example:
	// if (req.http.Foo && /* comment */ req.http.Bar) { ... } // -> trim  /* comment */ token
	// if (
	//   req.http.Foo &&
	//   # Some line comment here // trim this line
	//   req.http,Bar
	// ) { ... }
	prefix, ok := p.prefixParsers[p.curToken.Type]
	if !ok {
		return nil, errors.WithStack(UndefinedPrefix(p.curToken))
	}

	left, err := prefix()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// same as prefix expression
	for !p.peekTokenIs(token.SEMICOLON) && precedence < p.peekPrecedence() {
		infix, ok := p.infixParsers[p.peekToken.Type]
		if !ok {
			return left, nil
		}
		p.nextToken()
		left, err = infix(left)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		continue
	}

	return left, nil
}

// nolint: unparam
func (p *Parser) parseIdent() *ast.Ident {
	return &ast.Ident{
		Meta:  ast.New(p.curToken, 0),
		Value: p.curToken.Literal,
	}
}

// nolint: unparam
func (p *Parser) parseIP() *ast.IP {
	return &ast.IP{
		Meta:  ast.New(p.curToken, 0),
		Value: p.curToken.Literal,
	}
}

// nolint: unparam
func (p *Parser) parseString() *ast.String {
	return &ast.String{
		Meta:  ast.New(p.curToken, 0),
		Value: p.curToken.Literal,
	}
}

func (p *Parser) parseInteger() (*ast.Integer, error) {
	v, err := strconv.ParseInt(p.curToken.Literal, 10, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "INTEGER"))
	}

	return &ast.Integer{
		Meta:  ast.New(p.curToken, 0),
		Value: v,
	}, nil
}

func (p *Parser) parseFloat() (*ast.Float, error) {
	v, err := strconv.ParseFloat(p.curToken.Literal, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "FLOAT"))
	}

	return &ast.Float{
		Meta:  ast.New(p.curToken, 0),
		Value: v,
	}, nil
}

// nolint: unparam
func (p *Parser) parseBoolean() *ast.Boolean {
	return &ast.Boolean{
		Meta:  ast.New(p.curToken, 0),
		Value: p.curToken.Type == token.TRUE,
	}
}

func (p *Parser) parseRTime() (*ast.RTime, error) {
	var value string

	switch {
	case strings.HasSuffix(p.curToken.Literal, "ms"):
		value = strings.TrimSuffix(p.curToken.Literal, "ms")
	case strings.HasSuffix(p.curToken.Literal, "s"):
		value = strings.TrimSuffix(p.curToken.Literal, "s")
	case strings.HasSuffix(p.curToken.Literal, "m"):
		value = strings.TrimSuffix(p.curToken.Literal, "m")
	case strings.HasSuffix(p.curToken.Literal, "h"):
		value = strings.TrimSuffix(p.curToken.Literal, "h")
	case strings.HasSuffix(p.curToken.Literal, "d"):
		value = strings.TrimSuffix(p.curToken.Literal, "d")
	case strings.HasSuffix(p.curToken.Literal, "y"):
		value = strings.TrimSuffix(p.curToken.Literal, "y")
	default:
		return nil, errors.WithStack(TypeConversionError(p.curToken, "RTIME"))
	}

	if _, err := strconv.ParseFloat(value, 64); err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "RTIME"))
	}
	return &ast.RTime{
		Meta:  ast.New(p.curToken, 0),
		Value: p.curToken.Literal,
	}, nil
}

func (p *Parser) parsePrefixExpression() (*ast.PrefixExpression, error) {
	exp := &ast.PrefixExpression{
		Meta:     ast.New(p.curToken, 0),
		Operator: p.curToken.Literal,
	}

	p.nextToken()
	var err error
	exp.Right, err = p.parseExpression(PREFIX)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return exp, nil
}

func (p *Parser) parseGroupedExpression() (*ast.GroupedExpression, error) {
	exp := &ast.GroupedExpression{
		Meta: ast.New(p.curToken, 0, p.comments()),
	}

	p.nextToken()
	var err error
	exp.Right, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	exp.Meta.Infix = p.comments()

	return exp, nil
}

// NOTE: On VCL, if expression syntax is defined like "if(cond, consequence, alternative)"
func (p *Parser) parseIfExpression() (*ast.IfExpression, error) {
	exp := &ast.IfExpression{
		Meta: ast.New(p.curToken, 0, p.comments()),
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}
	exp.Meta.Infix = p.comments()
	p.nextToken()

	cond, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Condition = cond

	if !p.expectPeek(token.COMMA) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
	}
	p.nextToken()

	exp.Consequence, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.COMMA) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
	}
	p.nextToken()

	exp.Alternative, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	exp.Meta.Trailing = p.comments()

	// if expression is an expression so do not check trailing semicolon
	return exp, nil
}

// nolint: gocognit
func (p *Parser) parseIfStatement(nest int) (*ast.IfStatement, error) {
	exp := &ast.IfStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}
	p.nextToken()

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}
	exp.Meta.Infix = p.comments()
	p.nextToken()

	cond, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Condition = cond

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	exp.Consequence, err = p.parseBlockStatement(nest + 1)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if !p.expectPeek(token.RIGHT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_BRACE"))
	}

	// If statement may have some "else if" or "else" as another/alternative statement.
	// Note that before each statement, user could write comment
	for {
		switch p.peekToken.Type {
		case token.ELSE: // else
			p.nextToken()
			if p.peekTokenIs(token.IF) { // else if
				p.nextToken()
				another, err := p.parseAnotherIfStatement(nest)
				if err != nil {
					return nil, errors.WithStack(err)
				}
				exp.Another = append(exp.Another, another)
				continue
			}

			// only "else"
			if !p.expectPeek(token.LEFT_BRACE) {
				return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
			}
			exp.AlternativeComments = p.comments()
			exp.Alternative, err = p.parseBlockStatement(nest + 1)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if c, ok := p.expectTrail(token.RIGHT_BRACE); !ok {
				return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_BRACE"))
			} else {
				exp.Meta.Trailing = c
			}
			goto FINISH
		case token.ELSEIF, token.ELSIF: // elseif, elsif
			p.nextToken()
			another, err := p.parseAnotherIfStatement(nest)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			exp.Another = append(exp.Another, another)
			continue
		}
		goto FINISH
	}
FINISH:
	return exp, nil
}

// AnotherIfStatement is very similar to IfStatement but always do not have alternative statement.
func (p *Parser) parseAnotherIfStatement(nest int) (*ast.IfStatement, error) {
	exp := &ast.IfStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}
	exp.Meta.Infix = p.comments()
	p.nextToken()

	cond, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Condition = cond

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	exp.Consequence, err = p.parseBlockStatement(nest + 1)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if !p.expectPeek(token.RIGHT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_BRACE"))
	}
	return exp, nil
}

func (p *Parser) parseInfixExpression(left ast.Expression) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Meta:     ast.New(p.curToken, 0, p.comments()),
		Operator: p.curToken.Literal,
		Left:     left,
	}

	precedence := p.curPrecedence()
	p.nextToken()
	var err error
	exp.Right, err = p.parseExpression(precedence)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return exp, nil
}

func (p *Parser) parseInfixStringConcatExpression(left ast.Expression) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Meta:     ast.New(p.curToken, 0, p.comments()),
		Operator: "+",
		Left:     left,
	}

	precedence := p.curPrecedence()
	var err error
	exp.Right, err = p.parseExpression(precedence)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return exp, nil
}

func (p *Parser) parseUnsetStatement(nest int) (*ast.UnsetStatement, error) {
	stmt := &ast.UnsetStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.parseIdent()

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

func (p *Parser) parseRemoveStatement(nest int) (*ast.RemoveStatement, error) {
	stmt := &ast.RemoveStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.parseIdent()

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

// nolint: dupl
func (p *Parser) parseAddStatement(nest int) (*ast.AddStatement, error) {
	stmt := &ast.AddStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.parseIdent()

	if !isAssignmentOperator(p.peekToken) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, assignmentOperatorLiterals...))
	}
	stmt.Ident.Trailing = p.comments()
	p.nextToken() // assignment operator
	stmt.Operator = &ast.Operator{
		Token:    p.curToken,
		Operator: p.curToken.Literal,
	}
	p.nextToken() // left expression token

	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = exp

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}
	return stmt, nil
}

func (p *Parser) parseEsiStatement(nest int) (*ast.EsiStatement, error) {
	stmt := &ast.EsiStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}
	return stmt, nil
}

func (p *Parser) parseRestartStatement(nest int) (*ast.RestartStatement, error) {
	stmt := &ast.RestartStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}
	return stmt, nil
}

func (p *Parser) parseCallStatement(nest int) (*ast.CallStatement, error) {
	stmt := &ast.CallStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Subroutine = p.parseIdent()

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

func (p *Parser) parseDeclareStatement(nest int) (*ast.DeclareStatement, error) {
	stmt := &ast.DeclareStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	// Declare Syntax is declare [IDENT:"local"] [IDENT:variable name] [IDENT:VCL type]
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	if p.curToken.Literal != "local" {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "local"))
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Name = p.parseIdent()

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.ValueType = p.parseIdent()

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

func (p *Parser) parseErrorStatement(nest int) (*ast.ErrorStatement, error) {
	stmt := &ast.ErrorStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	// error code token must be ident or integer
	var err error
	switch p.peekToken.Type {
	case token.INT:
		p.nextToken()
		stmt.Code, err = p.parseInteger()
	case token.IDENT:
		p.nextToken()
		stmt.Code = p.parseIdent()
	default:
		err = UnexpectedToken(p.peekToken)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Optional expression
	if !p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
		stmt.Argument, err = p.parseExpression(LOWEST)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

func (p *Parser) parseLogStatement(nest int) (*ast.LogStatement, error) {
	stmt := &ast.LogStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	p.nextToken()
	var err error
	stmt.Value, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

func (p *Parser) parseReturnStatement(nest int) (*ast.ReturnStatement, error) {
	stmt := &ast.ReturnStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	// return statement may not have any arguments
	// https://developer.fastly.com/reference/vcl/statements/return/
	if p.peekTokenIs(token.SEMICOLON) {
		if c, ok := p.expectTrail(token.SEMICOLON); !ok {
			return nil, errors.WithStack(MissingSemicolon(p.peekToken))
		} else {
			stmt.Meta.Trailing = c
		}
		return stmt, nil
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.parseIdent()

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	stmt.Meta.Trailing = p.comments()

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

func (p *Parser) parseSyntheticStatement(nest int) (*ast.SyntheticStatement, error) {
	stmt := &ast.SyntheticStatement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	p.nextToken()
	var err error
	stmt.Value, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

func (p *Parser) parseSyntheticBase64Statement(nest int) (*ast.SyntheticBase64Statement, error) {
	stmt := &ast.SyntheticBase64Statement{
		Meta: ast.New(p.curToken, nest, p.comments()),
	}

	p.nextToken()
	var err error
	stmt.Value, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if c, ok := p.expectTrail(token.SEMICOLON); !ok {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	} else {
		stmt.Meta.Trailing = c
	}

	return stmt, nil
}

func (p *Parser) parseFunctionCallExpression(fn ast.Expression) (ast.Expression, error) {
	ident, ok := fn.(*ast.Ident)
	if !ok {
		return nil, fmt.Errorf("Function name must be IDENT")
	}
	exp := &ast.FunctionCallExpression{
		Meta:     ast.New(p.curToken, 0, p.comments()),
		Function: ident,
	}

	args, err := p.parseExpressionList(token.RIGHT_PAREN)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Arguments = args
	return exp, nil
}

func (p *Parser) parseExpressionList(end token.TokenType) ([]ast.Expression, error) {
	list := []ast.Expression{}

	if p.peekTokenIs(end) {
		p.nextToken() // point to "end" token
		return list, nil
	}

	p.nextToken()
	item, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	list = append(list, item)

	for p.peekTokenIs(token.COMMA) {
		p.nextToken() // point to COMMA
		p.nextToken() // point to next argument expression
		item, err := p.parseExpression(LOWEST)
		if err != nil {
			return nil, err
		}
		list = append(list, item)
	}

	if !p.expectPeek(end) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken))
	}

	return list, nil
}
