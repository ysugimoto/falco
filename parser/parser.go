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
	prefixParser func(ast.Comments) (ast.Expression, error)
	infixParser  func(ast.Expression, ast.Comments) (ast.Expression, error)
)

type Parser struct {
	l *lexer.Lexer

	prevToken token.Token
	curToken  token.Token
	peekToken token.Token

	prefixParsers map[token.TokenType]prefixParser
	infixParsers  map[token.TokenType]infixParser
}

func New(l *lexer.Lexer) *Parser {
	p := &Parser{
		l: l,
	}

	p.prefixParsers = map[token.TokenType]prefixParser{
		token.IDENT:      func(c ast.Comments) (ast.Expression, error) { return p.parseIdent(c) },
		token.STRING:     func(c ast.Comments) (ast.Expression, error) { return p.parseString(c) },
		token.INT:        func(c ast.Comments) (ast.Expression, error) { return p.parseInteger(c) },
		token.FLOAT:      func(c ast.Comments) (ast.Expression, error) { return p.parseFloat(c) },
		token.RTIME:      func(c ast.Comments) (ast.Expression, error) { return p.parseRTime(c) },
		token.NOT:        func(c ast.Comments) (ast.Expression, error) { return p.parsePrefixExpression(c) },
		token.MINUS:      func(c ast.Comments) (ast.Expression, error) { return p.parsePrefixExpression(c) },
		token.PLUS:       func(c ast.Comments) (ast.Expression, error) { return p.parsePrefixExpression(c) },
		token.TRUE:       func(c ast.Comments) (ast.Expression, error) { return p.parseBoolean(c) },
		token.FALSE:      func(c ast.Comments) (ast.Expression, error) { return p.parseBoolean(c) },
		token.LEFT_PAREN: func(c ast.Comments) (ast.Expression, error) { return p.parseGroupedExpression(c) },
		token.IF:         func(c ast.Comments) (ast.Expression, error) { return p.parseIfExpression(c) },
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
	p.peekToken = p.l.NextToken()
}

func (p *Parser) curTokenIs(t token.TokenType) bool {
	return p.curToken.Type == t
}

func (p *Parser) peekTokenIs(t token.TokenType) bool {
	return p.peekToken.Type == t
}

func (p *Parser) expectPeek(t token.TokenType) bool {
	for p.peekTokenIs(token.LF) {
		p.nextToken()
	}
	if !p.peekTokenIs(t) {
		return false
	}
	p.nextToken()
	return true
}

func (p *Parser) comments(lv int) ast.Comments {
	cs := ast.Comments{}

	for {
		if p.curTokenIs(token.LF) {
			p.nextToken()
			continue
		} else if !p.curTokenIs(token.COMMENT) {
			break
		}
		cs = append(cs, &ast.Comment{
			Token: p.curToken,
			Value: p.curToken.Literal,
		})
		p.nextToken()
	}
	return cs
}

func (p *Parser) peekComments() ast.Comments {
	cs := ast.Comments{}

	for {
		if p.peekTokenIs(token.LF) {
			p.nextToken()
			continue
		} else if !p.peekTokenIs(token.COMMENT) {
			break
		}
		p.nextToken()
		cs = append(cs, &ast.Comment{
			Token: p.curToken,
			Value: p.curToken.Literal,
		})
	}
	return cs
}

func (p *Parser) trailComment() ast.Comments {
	cs := ast.Comments{}

	for {
		if p.peekTokenIs(token.LF) {
			p.nextToken()
			break
		} else if !p.peekTokenIs(token.COMMENT) {
			break
		}
		p.nextToken()
		cs = append(cs, &ast.Comment{
			Token: p.curToken,
			Value: p.curToken.Literal,
		})
	}
	return cs
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

	comments := p.comments(0)

	switch p.curToken.Type {
	case token.ACL:
		stmt, err = p.parseAclDeclaration(comments)
	case token.IMPORT:
		stmt, err = p.parseImportStatement(comments)
	case token.INCLUDE:
		stmt, err = p.parseIncludeStatement(comments)
	case token.BACKEND:
		stmt, err = p.parseBackendDeclaration(comments)
	case token.DIRECTOR:
		stmt, err = p.parseDirectorDeclaration(comments)
	case token.TABLE:
		stmt, err = p.parseTableDeclaration(comments)
	case token.SUBROUTINE:
		stmt, err = p.parseSubroutineDeclaration(comments)
	default:
		err = UnexpectedToken(p.curToken)
	}

	if err != nil {
		return nil, errors.WithStack(err)
	}
	p.nextToken()
	return stmt, nil
}

func (p *Parser) parseAclDeclaration(comments ast.Comments) (*ast.AclDeclaration, error) {
	acl := &ast.AclDeclaration{
		Meta: ast.New(p.curToken, 0, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.IDENT))
	}

	var err error
	acl.Name, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.LEFT_BRACE))
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		cidr, err := p.parseAclCidr()
		if err != nil {
			return nil, errors.WithStack(err)
		} else if cidr != nil {
			acl.CIDRs = append(acl.CIDRs, cidr)
		}
	}
	p.nextToken() // on RIGHT_BRACE
	acl.Meta.Trailing = p.trailComment()
	return acl, nil
}

func (p *Parser) parseAclCidr() (*ast.AclCidr, error) {
	comments := p.peekComments()
	p.nextToken()

	cidr := &ast.AclCidr{
		Meta: ast.New(p.curToken, 1, comments),
	}
	// Set inverse if "!" token exists
	var err error
	if p.curTokenIs(token.NOT) {
		cidr.Inverse = &ast.Boolean{
			Meta:  ast.New(p.curToken, 0),
			Value: true,
		}
		p.nextToken()
	}

	if !p.curTokenIs(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.STRING))
	}

	cidr.IP, err = p.parseIP(ast.Comments{})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Add mask token if found in "/" on next token
	if p.peekTokenIs(token.SLASH) {
		p.nextToken()
		c := p.peekComments()
		if !p.expectPeek(token.INT) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.INT))
		}

		cidr.Mask, err = p.parseInteger(c)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	cidr.Meta.Trailing = p.trailComment()

	return cidr, nil
}

func (p *Parser) parseImportStatement(comments ast.Comments) (*ast.ImportStatement, error) {
	i := &ast.ImportStatement{
		Meta: ast.New(p.curToken, 0, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	i.Name, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	i.Meta.Trailing = p.trailComment()

	return i, nil
}

func (p *Parser) parseIncludeStatement(comments ast.Comments) (ast.Statement, error) {
	i := &ast.IncludeStatement{
		Meta: ast.New(p.curToken, 0, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}

	var err error
	i.Module, err = p.parseString(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	i.Meta.Trailing = p.trailComment()

	return i, nil
}

func (p *Parser) parseBackendDeclaration(comments ast.Comments) (*ast.BackendDeclaration, error) {
	b := &ast.BackendDeclaration{
		Meta: ast.New(p.curToken, 0, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	b.Name, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

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

	p.nextToken() // RIGHT_BRACE
	b.Meta.Trailing = p.trailComment()
	return b, nil
}

func (p *Parser) parseBackendProperty(nestLevel int) (*ast.BackendProperty, error) {
	comments := p.peekComments()
	if !p.expectPeek(token.DOT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "DOT"))
	}

	prop := &ast.BackendProperty{
		Meta: ast.New(p.curToken, nestLevel, comments),
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	prop.Key, err = p.parseIdent(ast.Comments{})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.ASSIGN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
	}

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
		p.nextToken() // point to RIGHT_BRACE
		probe.Meta.Trailing = p.trailComment()
		prop.Value = probe
		return prop, nil
	}

	// Otherwise, parse expression
	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	prop.Value = exp

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	prop.Meta.Trailing = p.trailComment()
	return prop, nil
}

func (p *Parser) parseDirectorDeclaration(comments ast.Comments) (*ast.DirectorDeclaration, error) {
	d := &ast.DirectorDeclaration{
		Meta: ast.New(p.curToken, 0, comments),
	}

	// director name
	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	d.Name, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// director type
	cc := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	d.DirectorType, err = p.parseIdent(cc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.parseDirectorProperty()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		d.Properties = append(d.Properties, prop)
	}
	p.nextToken() // RIGHT_BRACE
	d.Meta.Trailing = p.trailComment()
	return d, nil
}

func (p *Parser) parseDirectorProperty() (ast.Expression, error) {
	comments := p.peekComments()

	switch p.peekToken.Type {
	// single property definition like ".quorum = 10%;"
	case token.DOT:
		p.nextToken()
		prop := &ast.DirectorProperty{
			Meta: ast.New(p.curToken, 1, comments),
		}

		// token may token.BACKEND because backend object has ".backend" property key
		if !p.expectPeek(token.IDENT) && !p.expectPeek(token.BACKEND) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
		}

		var err error
		prop.Key, err = p.parseIdent(ast.Comments{})
		if err != nil {
			return nil, errors.WithStack(err)
		}

		if !p.expectPeek(token.ASSIGN) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
		}

		p.nextToken() // point to expression start token

		exp, err := p.parseExpression(LOWEST)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prop.Value = exp

		if !p.expectPeek(token.SEMICOLON) {
			return nil, errors.WithStack(MissingSemicolon(p.curToken))
		}
		prop.Meta.Trailing = p.trailComment()

		return prop, nil
	// object definition e.g. { .backend = F_origin_1; .weight = 1; }
	case token.LEFT_BRACE:
		p.nextToken()
		prop := &ast.DirectorBackendObject{
			Meta: ast.New(p.curToken, 1, comments),
		}

		for !p.peekTokenIs(token.RIGHT_BRACE) {
			pp, err := p.parseDirectorProperty()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			prop.Values = append(prop.Values, pp.(*ast.DirectorProperty))
		}
		p.nextToken() // point to RIGHT_BRACE
		prop.Meta.Trailing = p.trailComment()

		return prop, nil
	default:
		return nil, errors.WithStack(UnexpectedToken(p.peekToken))
	}
}

func (p *Parser) parseTableDeclaration(comments ast.Comments) (*ast.TableDeclaration, error) {
	t := &ast.TableDeclaration{
		Meta: ast.New(p.curToken, 0, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	t.Name, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Table value type is optional
	cc := p.peekComments()
	if p.peekTokenIs(token.IDENT) {
		p.nextToken()
		t.ValueType, err = p.parseIdent(cc)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.parseTableProperty()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		t.Properties = append(t.Properties, prop)
	}
	p.nextToken() // RIGHT_BRACE
	t.Meta.Trailing = p.trailComment()

	return t, nil
}

func (p *Parser) parseTableProperty() (*ast.TableProperty, error) {
	comments := p.peekComments()
	if !p.expectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}

	prop := &ast.TableProperty{
		Meta: ast.New(p.curToken, 1, comments),
	}

	var err error
	prop.Key, err = p.parseString(ast.Comments{})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.COLON) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COLON"))
	}

	c := p.peekComments()
	switch p.peekToken.Type {
	case token.STRING:
		p.nextToken()
		prop.Value = &ast.String{
			Meta:  ast.New(p.curToken, 0, c),
			Value: p.curToken.Literal,
		}
	case token.ACL, token.BACKEND:
		p.nextToken()
		prop.Value = &ast.Ident{
			Meta:  ast.New(p.curToken, 0, c),
			Value: p.curToken.Literal,
		}
	case token.TRUE:
		p.nextToken()
		prop.Value = &ast.Boolean{
			Meta:  ast.New(p.curToken, 0, c),
			Value: true,
		}
	case token.FALSE:
		p.nextToken()
		prop.Value = &ast.Boolean{
			Meta:  ast.New(p.curToken, 0, c),
			Value: false,
		}
	case token.FLOAT:
		p.nextToken()
		v, err := strconv.ParseFloat(p.curToken.Literal, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prop.Value = &ast.Float{
			Meta:  ast.New(p.curToken, 0, c),
			Value: v,
		}
	case token.INT:
		p.nextToken()
		v, err := strconv.ParseInt(p.curToken.Literal, 10, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		prop.Value = &ast.Integer{
			Meta:  ast.New(p.curToken, 0, c),
			Value: v,
		}
	case token.RTIME:
		p.nextToken()
		prop.Value = &ast.RTime{
			Meta:  ast.New(p.curToken, 0, c),
			Value: p.curToken.Literal,
		}
	default:
		return nil, errors.WithStack(UnexpectedToken(p.peekToken))
	}

	if p.expectPeek(token.COMMA) {
		prop.Meta.Trailing = p.trailComment()
	} else {
		prop.Meta.Trailing = p.trailComment()
		// But last table item does not need commma
		if !p.peekTokenIs(token.RIGHT_BRACE) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
		}
	}
	return prop, nil
}

func (p *Parser) parseSubroutineDeclaration(comments ast.Comments) (*ast.SubroutineDeclaration, error) {
	s := &ast.SubroutineDeclaration{
		Meta: ast.New(p.curToken, 0, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	s.Name, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	block, err := p.parseBlockStatement(1)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	s.Block = block
	s.Meta.Trailing = p.trailComment()

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

		comments := p.peekComments()

		switch p.peekToken.Type {
		case token.SET:
			p.nextToken()
			stmt, err = p.parseSetStatement(comments, nest)
		case token.UNSET:
			p.nextToken()
			stmt, err = p.parseUnsetStatement(comments, nest)
		case token.REMOVE:
			p.nextToken()
			stmt, err = p.parseRemoveStatement(comments, nest)
		case token.ADD:
			p.nextToken()
			stmt, err = p.parseAddStatement(comments, nest)
		case token.CALL:
			p.nextToken()
			stmt, err = p.parseCallStatement(comments, nest)
		case token.DECLARE:
			p.nextToken()
			stmt, err = p.parseDeclareStatement(comments, nest)
		case token.ERROR:
			p.nextToken()
			stmt, err = p.parseErrorStatement(comments, nest)
		case token.ESI:
			p.nextToken()
			stmt, err = p.parseEsiStatement(comments, nest)
		case token.LOG:
			p.nextToken()
			stmt, err = p.parseLogStatement(comments, nest)
		case token.RESTART:
			p.nextToken()
			stmt, err = p.parseRestartStatement(comments, nest)
		case token.RETURN:
			p.nextToken()
			stmt, err = p.parseReturnStatement(comments, nest)
		case token.SYNTHETIC:
			p.nextToken()
			stmt, err = p.parseSyntheticStatement(comments, nest)
		case token.SYNTHETIC_BASE64:
			p.nextToken()
			stmt, err = p.parseSyntheticBase64Statement(comments, nest)
		case token.IF:
			p.nextToken()
			stmt, err = p.parseIfStatement(comments, nest)
		case token.COMMENT:
			p.nextToken()
			continue
		default:
			err = UnexpectedToken(p.peekToken)
		}
		if err != nil {
			return nil, errors.WithStack(err)
		}
		b.Statements = append(b.Statements, stmt)
	}

	p.nextToken() // point to RIGHT_BRACE that end of block
	return b, nil
}

func (p *Parser) parseSetStatement(comments ast.Comments, nest int) (*ast.SetStatement, error) {
	stmt := &ast.SetStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	stmt.Ident, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

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

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}
	stmt.Meta.Trailing = p.trailComment()

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
	c := p.comments(0)
	prefix, ok := p.prefixParsers[p.curToken.Type]
	if !ok {
		return nil, errors.WithStack(UndefinedPrefix(p.curToken))
	}

	left, err := prefix(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// same as prefix expression
	for {
		cc := p.peekComments()
		if !p.peekTokenIs(token.SEMICOLON) && precedence < p.peekPrecedence() {
			infix, ok := p.infixParsers[p.peekToken.Type]
			if !ok {
				return left, nil
			}
			p.nextToken()
			left, err = infix(left, cc)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			continue
		}
		break
	}
	// TODO: store trailing comments
	p.trailComment()

	return left, nil
}

func (p *Parser) parseIdent(comments ast.Comments) (*ast.Ident, error) {
	n := &ast.Ident{
		Meta:  ast.New(p.curToken, 0, comments),
		Value: p.curToken.Literal,
	}
	n.Meta.Trailing = p.trailComment()
	return n, nil
}

func (p *Parser) parseIP(comments ast.Comments) (*ast.IP, error) {
	n := &ast.IP{
		Meta:  ast.New(p.curToken, 0, comments),
		Value: p.curToken.Literal,
	}
	n.Meta.Trailing = p.trailComment()
	return n, nil
}

func (p *Parser) parseString(comments ast.Comments) (*ast.String, error) {
	n := &ast.String{
		Meta:  ast.New(p.curToken, 0, comments),
		Value: p.curToken.Literal,
	}
	n.Meta.Trailing = p.trailComment()
	return n, nil
}

func (p *Parser) parseInteger(comments ast.Comments) (*ast.Integer, error) {
	v, err := strconv.ParseInt(p.curToken.Literal, 10, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "INTEGER"))
	}

	n := &ast.Integer{
		Meta:  ast.New(p.curToken, 0, comments),
		Value: v,
	}
	n.Meta.Trailing = p.trailComment()
	return n, nil
}

func (p *Parser) parseFloat(comments ast.Comments) (*ast.Float, error) {
	v, err := strconv.ParseFloat(p.curToken.Literal, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "FLOAT"))
	}

	n := &ast.Float{
		Meta:  ast.New(p.curToken, 0, comments),
		Value: v,
	}
	n.Meta.Trailing = p.trailComment()
	return n, nil
}

func (p *Parser) parseBoolean(comments ast.Comments) (*ast.Boolean, error) {
	b := &ast.Boolean{
		Meta:  ast.New(p.curToken, 0, comments),
		Value: p.curToken.Type == token.TRUE,
	}
	b.Meta.Trailing = p.trailComment()
	return b, nil
}

func (p *Parser) parseRTime(comments ast.Comments) (*ast.RTime, error) {
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
	r := &ast.RTime{
		Meta:  ast.New(p.curToken, 0, comments),
		Value: p.curToken.Literal,
	}
	r.Meta.Trailing = p.trailComment()
	return r, nil
}

func (p *Parser) parsePrefixExpression(comments ast.Comments) (*ast.PrefixExpression, error) {
	exp := &ast.PrefixExpression{
		Meta:     ast.New(p.curToken, 0, comments),
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

func (p *Parser) parseGroupedExpression(comments ast.Comments) (*ast.GroupedExpression, error) {
	exp := &ast.GroupedExpression{
		Meta: ast.New(p.curToken, 0, comments),
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

	return exp, nil
}

// NOTE: On VCL, if expression syntax is defined like "if(cond, consequence, alternative)"
func (p *Parser) parseIfExpression(comments ast.Comments) (*ast.IfExpression, error) {
	exp := &ast.IfExpression{
		Meta: ast.New(p.curToken, 0, comments),
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}
	p.nextToken()

	cond, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Condition = cond

	p.peekComments()
	if !p.expectPeek(token.COMMA) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
	}
	p.nextToken()

	exp.Consequence, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	p.peekComments()
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
	// if expression is an expression so do not check trailing semicolon
	return exp, nil
}

func (p *Parser) parseIfStatement(comments ast.Comments, nest int) (*ast.IfStatement, error) {
	exp := &ast.IfStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}
	p.nextToken()

	cond, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Condition = cond

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	// TODO: store trailing comments
	p.peekComments()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	exp.Consequence, err = p.parseBlockStatement(nest + 1)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// If statement may have some "else if" or "else" as another/alternative statement.
	// Note that before each statement, user could write comment
	for {
		comments := p.peekComments()
		switch p.peekToken.Type {
		case token.ELSE: // else
			p.nextToken()
			if p.peekTokenIs(token.IF) { // else if
				p.nextToken()
				another, err := p.parseAnotherIfStatement(comments, nest)
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
			exp.AlternativeComments = comments
			exp.Alternative, err = p.parseBlockStatement(nest + 1)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			exp.Meta.Trailing = p.peekComments()
			goto FINISH
		case token.ELSEIF, token.ELSIF: // elseif, elsif
			p.nextToken()
			another, err := p.parseAnotherIfStatement(comments, nest)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			exp.Another = append(exp.Another, another)
			continue
		}
		exp.Meta.Trailing = comments
		goto FINISH
	}
FINISH:
	return exp, nil
}

// AnotherIfStatement is very similar to IfStatement but always do not have alternative statement.
func (p *Parser) parseAnotherIfStatement(comments ast.Comments, nest int) (*ast.IfStatement, error) {
	exp := &ast.IfStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}
	p.nextToken()

	cond, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Condition = cond

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	// TODO: store trailing comments
	p.peekComments()

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	exp.Consequence, err = p.parseBlockStatement(nest + 1)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Meta.Trailing = p.trailComment()
	return exp, nil
}

func (p *Parser) parseInfixExpression(left ast.Expression, comments ast.Comments) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Meta:     ast.New(p.curToken, 0, comments),
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

func (p *Parser) parseInfixStringConcatExpression(left ast.Expression, comments ast.Comments) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Meta:     ast.New(p.curToken, 0, comments),
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

func (p *Parser) parseUnsetStatement(comments ast.Comments, nest int) (*ast.UnsetStatement, error) {
	stmt := &ast.UnsetStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	stmt.Ident, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	stmt.Meta.Trailing = p.trailComment()
	return stmt, nil
}

func (p *Parser) parseRemoveStatement(comments ast.Comments, nest int) (*ast.RemoveStatement, error) {
	stmt := &ast.RemoveStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	stmt.Ident, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	stmt.Meta.Trailing = p.trailComment()
	return stmt, nil
}

func (p *Parser) parseAddStatement(comments ast.Comments, nest int) (*ast.AddStatement, error) {
	stmt := &ast.AddStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	stmt.Ident, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !isAssignmentOperator(p.peekToken) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, assignmentOperatorLiterals...))
	}
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

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	stmt.Meta.Trailing = p.trailComment()
	return stmt, nil
}

func (p *Parser) parseEsiStatement(comments ast.Comments, nest int) (*ast.EsiStatement, error) {
	stmt := &ast.EsiStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	stmt.Meta.Trailing = p.trailComment()
	return stmt, nil
}

func (p *Parser) parseRestartStatement(comments ast.Comments, nest int) (*ast.RestartStatement, error) {
	stmt := &ast.RestartStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	stmt.Meta.Trailing = p.trailComment()
	return stmt, nil
}

func (p *Parser) parseCallStatement(comments ast.Comments, nest int) (*ast.CallStatement, error) {
	stmt := &ast.CallStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	stmt.Subroutine, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	stmt.Meta.Trailing = p.trailComment()
	return stmt, nil
}

func (p *Parser) parseDeclareStatement(comments ast.Comments, nest int) (*ast.DeclareStatement, error) {
	stmt := &ast.DeclareStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	// Declare Syntax is declare [IDENT:"local"] [IDENT:variable name] [IDENT:VCL type]
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	if p.curToken.Literal != "local" {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "local"))
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	stmt.Name, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	cc := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.ValueType, err = p.parseIdent(cc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	stmt.Meta.Trailing = p.trailComment()
	return stmt, nil
}

func (p *Parser) parseErrorStatement(comments ast.Comments, nest int) (*ast.ErrorStatement, error) {
	stmt := &ast.ErrorStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	c := p.peekComments()
	// error code token must be ident or integer
	var err error
	switch p.peekToken.Type {
	case token.INT:
		p.nextToken()
		stmt.Code, err = p.parseInteger(c)
	case token.IDENT:
		p.nextToken()
		stmt.Code, err = p.parseIdent(c)
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

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	stmt.Meta.Trailing = p.trailComment()
	return stmt, nil
}

func (p *Parser) parseLogStatement(comments ast.Comments, nest int) (*ast.LogStatement, error) {
	stmt := &ast.LogStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	p.nextToken()
	var err error
	stmt.Value, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	stmt.Meta.Trailing = p.trailComment()
	return stmt, nil
}

func (p *Parser) parseReturnStatement(comments ast.Comments, nest int) (*ast.ReturnStatement, error) {
	stmt := &ast.ReturnStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	// return statement may not have any arguments
	// https://developer.fastly.com/reference/vcl/statements/return/
	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
		return stmt, nil
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}

	c := p.peekComments()
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	var err error
	stmt.Ident, err = p.parseIdent(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}
	stmt.Meta.Trailing = p.trailComment()

	return stmt, nil
}

func (p *Parser) parseSyntheticStatement(comments ast.Comments, nest int) (*ast.SyntheticStatement, error) {
	stmt := &ast.SyntheticStatement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	p.nextToken()
	var err error
	stmt.Value, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}
	stmt.Meta.Trailing = p.trailComment()

	return stmt, nil
}

func (p *Parser) parseSyntheticBase64Statement(comments ast.Comments, nest int) (*ast.SyntheticBase64Statement, error) {
	stmt := &ast.SyntheticBase64Statement{
		Meta: ast.New(p.curToken, nest, comments),
	}

	p.nextToken()
	var err error
	stmt.Value, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}
	stmt.Meta.Trailing = p.trailComment()

	return stmt, nil
}

func (p *Parser) parseFunctionCallExpression(fn ast.Expression, comments ast.Comments) (ast.Expression, error) {
	ident, ok := fn.(*ast.Ident)
	if !ok {
		return nil, fmt.Errorf("Function name must be IDENT")
	}
	exp := &ast.FunctionCallExpression{
		Meta:     ast.New(p.curToken, 0, comments),
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
