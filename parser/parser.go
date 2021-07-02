package parser

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/k0kubun/pp"
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

	prefixParsers map[token.TokenType]prefixParser
	infixParsers  map[token.TokenType]infixParser
}

// nolint: unused
func (p *Parser) debug(mark string) {
	fmt.Printf("[%s] curToken: %s / peekToken: %s\n", mark, p.curToken, p.peekToken)
}

func New(l *lexer.Lexer) *Parser {
	p := &Parser{
		l: l,
	}

	p.prefixParsers = map[token.TokenType]prefixParser{
		token.IDENT:      p.parseIdent,
		token.STRING:     p.parseString,
		token.INT:        p.parseInteger,
		token.FLOAT:      p.parseFloat,
		token.RTIME:      p.parseRTime,
		token.NOT:        p.parsePrefixExpression,
		token.MINUS:      p.parsePrefixExpression,
		token.PLUS:       p.parsePrefixExpression,
		token.TRUE:       p.parseBoolean,
		token.FALSE:      p.parseBoolean,
		token.LEFT_PAREN: p.parseGroupedExpression,
		token.IF:         p.parseIfExpression,
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
	if !p.peekTokenIs(t) {
		return false
	}
	p.nextToken()
	return true
}

func (p *Parser) collectComments(lv int) ast.Comments {
	cs := ast.Comments{}

	for p.curTokenIs(token.COMMENT) {
		cs = append(cs, &ast.CommentStatement{
			NestLevel: lv,
			Token:     p.curToken,
			Value:     p.curToken.Literal,
		})
		p.nextToken()
	}
	return cs
}

func (p *Parser) collectPeekComments(lv int) ast.Comments {
	cs := ast.Comments{}

	for p.peekTokenIs(token.COMMENT) {
		p.nextToken()
		cs = append(cs, &ast.CommentStatement{
			NestLevel: lv,
			Token:     p.curToken,
			Value:     p.curToken.Literal,
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

	comments := p.collectComments(0)

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
		Comments: comments,
		Token:    p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.IDENT))
	}

	acl.Name = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.LEFT_BRACE))
	}

	pc := p.collectPeekComments(1)
	for !p.peekTokenIs(token.RIGHT_BRACE) {
		cidr, err := p.parseAclCidr(pc)
		if err != nil {
			return nil, errors.WithStack(err)
		} else if cidr != nil {
			acl.CIDRs = append(acl.CIDRs, cidr)
		}
		pc = p.collectPeekComments(1)
	}
	p.nextToken() // on RIGHT_BRACE
	return acl, nil
}

func (p *Parser) parseAclCidr(comments ast.Comments) (*ast.AclCidr, error) {
	var inverse *ast.Boolean
	// Set inverse if "!" token exists
	if p.peekTokenIs(token.NOT) {
		inverse = &ast.Boolean{
			Token: p.peekToken,
			Value: true,
		}
		p.nextToken()
	}

	cidr := &ast.AclCidr{
		Comments: comments,
		Token:    p.curToken,
		Inverse:  inverse,
	}

	if !p.expectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.STRING))
	}

	cidr.IP = &ast.IP{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	// Add mask token if found in "/" on next token
	if p.peekTokenIs(token.SLASH) {
		p.nextToken()
		if !p.expectPeek(token.INT) {
			return nil, errors.WithStack(UnexpectedToken(p.peekToken, token.INT))
		}

		// Attempt to convert string to integer
		v, err := strconv.ParseInt(p.curToken.Literal, 10, 64)
		if err != nil {
			return nil, errors.WithStack(&ParseError{
				Token:   p.curToken,
				Message: fmt.Sprintf("Failed to convert IP mask as integer, got %s", p.curToken.Literal),
			})
		}
		cidr.Mask = &ast.Integer{
			Token: p.curToken,
			Value: v,
		}
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	return cidr, nil
}

func (p *Parser) parseImportStatement(comments ast.Comments) (*ast.ImportStatement, error) {
	i := &ast.ImportStatement{
		Comments: comments,
		Token:    p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	i.Value = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	return i, nil
}

func (p *Parser) parseIncludeStatement(comments ast.Comments) (ast.Statement, error) {
	i := &ast.IncludeStatement{
		Comments: comments,
		Token:    p.curToken,
	}

	if !p.expectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}

	i.Module = &ast.String{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	return i, nil
}

func (p *Parser) parseBackendDeclaration(comments ast.Comments) (*ast.BackendDeclaration, error) {
	b := &ast.BackendDeclaration{
		Token:    p.curToken,
		Comments: comments,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	b.Name = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	pc := p.collectPeekComments(1)
	for !p.peekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.parseBackendProperty(pc, 1)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		b.Properties = append(b.Properties, prop)
		pc = p.collectPeekComments(1)
	}

	p.nextToken() // RIGHT_BRACE
	return b, nil
}

func (p *Parser) parseBackendProperty(comments ast.Comments, nestLevel int) (*ast.BackendProperty, error) {
	if !p.expectPeek(token.DOT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "DOT"))
	}

	prop := &ast.BackendProperty{
		Token:    p.curToken,
		Comments: comments,
	}

	// Note: this context should allow token.BACKEND
	// because in director section, ".backend = example;" will present
	if !p.expectPeek(token.IDENT) && !p.expectPeek(token.BACKEND) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	prop.Key = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.ASSIGN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "ASSIGN"))
	}

	p.nextToken() // point to right token

	// When current token is "{", property key should be ".probe"
	if p.curTokenIs(token.LEFT_BRACE) {
		probe := &ast.BackendProbeObject{
			Token: p.curToken,
		}

		pc := p.collectPeekComments(nestLevel)
		for !p.peekTokenIs(token.RIGHT_BRACE) {
			pp, err := p.parseBackendProperty(pc, nestLevel+1)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			probe.Values = append(probe.Values, pp)
			pc = p.collectPeekComments(nestLevel)
		}
		p.nextToken()
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

	return prop, nil
}

func (p *Parser) parseDirectorDeclaration(comments ast.Comments) (*ast.DirectorDeclaration, error) {
	d := &ast.DirectorDeclaration{
		Comments: comments,
		Token:    p.curToken,
	}

	// director name
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	d.Name = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	// director type
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	d.DirectorType = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	pc := p.collectPeekComments(1)
	for !p.peekTokenIs(token.RIGHT_BRACE) {
		prop, err := p.parseDirectorProperty(pc)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		d.Properties = append(d.Properties, prop)
		pc = p.collectPeekComments(1)
	}
	p.nextToken() // RIGHT_BRACE
	return d, nil
}

func (p *Parser) parseDirectorProperty(comments ast.Comments) (ast.Expression, error) {
	switch p.peekToken.Type {
	// single property definition e.g ".quorum = 10%;"
	case token.DOT:
		p.nextToken()
		prop := &ast.DirectorProperty{
			Token:    p.curToken,
			Comments: comments,
		}
		if !p.expectPeek(token.IDENT) {
			// token may token.BACKEND because backend object has ".backend" property key
			if !p.expectPeek(token.BACKEND) {
				return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
			}
		}
		prop.Key = &ast.Ident{
			Token: p.curToken,
			Value: p.curToken.Literal,
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

		return prop, nil
	// object definition e.g. { .backend = F_origin_1; .weight = 1; }
	case token.LEFT_BRACE:
		p.nextToken()
		prop := &ast.DirectorBackendObject{
			Token:    p.curToken,
			Comments: comments,
		}
		pc := p.collectPeekComments(2)
		for !p.peekTokenIs(token.RIGHT_BRACE) {
			pp, err := p.parseDirectorProperty(pc)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			prop.Values = append(prop.Values, pp.(*ast.DirectorProperty))
			pc = p.collectPeekComments(2)
		}
		p.nextToken()

		return prop, nil
	default:
		return nil, errors.WithStack(UnexpectedToken(p.peekToken))
	}
}

func (p *Parser) parseTableDeclaration(comments ast.Comments) (*ast.TableDeclaration, error) {
	t := &ast.TableDeclaration{
		Token:    p.curToken,
		Comments: comments,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	t.Name = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	// Table value type is optional
	if p.peekTokenIs(token.IDENT) {
		p.nextToken()
		t.ValueType = &ast.Ident{
			Token: p.curToken,
			Value: p.curToken.Literal,
		}
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	pc := p.collectPeekComments(1)
	for !p.peekTokenIs(token.RIGHT_BRACE) {
		prop, comments, err := p.parseTableProperty(pc)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		t.Properties = append(t.Properties, prop)
		pc = comments
	}
	p.nextToken() // RIGHT_BRACE

	return t, nil
}

func (p *Parser) parseTableProperty(comments ast.Comments) (*ast.TableProperty, ast.Comments, error) {
	if !p.expectPeek(token.STRING) {
		return nil, nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}
	prop := &ast.TableProperty{
		Comments: comments,
		Token:    p.curToken,
		Key: &ast.String{
			Token: p.curToken,
			Value: p.curToken.Literal,
		},
	}

	if !p.expectPeek(token.COLON) {
		return nil, nil, errors.WithStack(UnexpectedToken(p.peekToken, "COLON"))
	}
	p.nextToken() // point to table value token

	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	prop.Value = exp
	ac := p.collectPeekComments(1)
	if !p.expectPeek(token.COMMA) {
		// But last table item does not need commma
		if !p.peekTokenIs(token.RIGHT_BRACE) {
			return nil, nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
		}
	}
	return prop, ac, nil
}

func (p *Parser) parseSubroutineDeclaration(comments ast.Comments) (*ast.SubroutineDeclaration, error) {
	s := &ast.SubroutineDeclaration{
		Comments: comments,
		Token:    p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	s.Name = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	block, err := p.parseBlockStatement(withNestLevel(1))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	s.Block = block

	return s, nil
}

func (p *Parser) parseBlockStatement(args ...OptionFunc) (*ast.BlockStatement, error) {
	arg := collect(args)
	b := &ast.BlockStatement{
		Token:      p.curToken, // LEFT_BRACE
		Comments:   arg.Comments,
		NestLevel:  arg.NestLevel,
		Statements: []ast.Statement{},
	}

	comments := p.collectPeekComments(arg.NestLevel)

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		var stmt ast.Statement
		var err error

		opts := []OptionFunc{
			withComments(comments),
			withNestLevel(arg.NestLevel),
		}

		switch p.peekToken.Type {
		case token.SET:
			p.nextToken()
			stmt, err = p.parseSetStatement(opts...)
		case token.UNSET:
			p.nextToken()
			stmt, err = p.parseUnsetStatement(opts...)
		case token.REMOVE:
			p.nextToken()
			stmt, err = p.parseRemoveStatement(opts...)
		case token.ADD:
			p.nextToken()
			stmt, err = p.parseAddStatement(opts...)
		case token.CALL:
			p.nextToken()
			stmt, err = p.parseCallStatement(opts...)
		case token.DECLARE:
			p.nextToken()
			stmt, err = p.parseDeclareStatement(opts...)
		case token.ERROR:
			p.nextToken()
			stmt, err = p.parseErrorStatement(opts...)
		case token.ESI:
			p.nextToken()
			stmt, err = p.parseEsiStatement(opts...)
		case token.LOG:
			p.nextToken()
			stmt, err = p.parseLogStatement(opts...)
		case token.RESTART:
			p.nextToken()
			stmt, err = p.parseRestartStatement(opts...)
		case token.RETURN:
			p.nextToken()
			stmt, err = p.parseReturnStatement(opts...)
		case token.SYNTHETIC:
			p.nextToken()
			stmt, err = p.parseSyntheticStatement(opts...)
		case token.SYNTHETIC_BASE64:
			p.nextToken()
			stmt, err = p.parseSyntheticBase64Statement(opts...)
		case token.IF:
			p.nextToken()
			stmt, err = p.parseIfStatement(opts...)
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
		comments = p.collectPeekComments(arg.NestLevel)
	}

	p.nextToken() // point to RIGHT_BRACE that end of block
	return b, nil
}

func (p *Parser) parseSetStatement(args ...OptionFunc) (*ast.SetStatement, error) {
	arg := collect(args)
	stmt := &ast.SetStatement{
		Comments:  arg.Comments,
		Token:     p.curToken,
		NestLevel: arg.NestLevel,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	stmt.Ident = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
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
		return nil, err
	}
	stmt.Value = exp

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
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
	p.collectComments(0)
	prefix, ok := p.prefixParsers[p.curToken.Type]
	if !ok {
		return nil, errors.WithStack(UndefinedPrefix(p.curToken))
	}

	left, err := prefix()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// same as prefix expression
	p.collectPeekComments(0)
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
	}

	return left, nil
}

func (p *Parser) parseIdent() (ast.Expression, error) {
	return &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}, nil
}

func (p *Parser) parseString() (ast.Expression, error) {
	return &ast.String{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}, nil
}

func (p *Parser) parseInteger() (ast.Expression, error) {
	v, err := strconv.ParseInt(p.curToken.Literal, 10, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "INTEGER"))
	}
	return &ast.Integer{
		Token: p.curToken,
		Value: v,
	}, nil
}

func (p *Parser) parseFloat() (ast.Expression, error) {
	v, err := strconv.ParseFloat(p.curToken.Literal, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "FLOAT"))
	}
	return &ast.Float{
		Token: p.curToken,
		Value: v,
	}, nil
}

func (p *Parser) parseBoolean() (ast.Expression, error) {
	b := &ast.Boolean{
		Token: p.curToken,
	}
	switch p.curToken.Type {
	case token.TRUE:
		b.Value = true
	case token.FALSE:
		b.Value = false
	default:
		return nil, errors.WithStack(TypeConversionError(p.curToken, "BOOL"))
	}
	return b, nil
}

func (p *Parser) parseRTime() (ast.Expression, error) {
	var value string
	var unit time.Duration

	switch {
	case strings.HasSuffix(p.curToken.Literal, "ms"):
		value = strings.TrimSuffix(p.curToken.Literal, "ms")
		unit = time.Millisecond
	case strings.HasSuffix(p.curToken.Literal, "s"):
		value = strings.TrimSuffix(p.curToken.Literal, "s")
		unit = time.Second
	case strings.HasSuffix(p.curToken.Literal, "m"):
		value = strings.TrimSuffix(p.curToken.Literal, "m")
		unit = time.Minute
	case strings.HasSuffix(p.curToken.Literal, "h"):
		value = strings.TrimSuffix(p.curToken.Literal, "h")
		unit = time.Hour
	case strings.HasSuffix(p.curToken.Literal, "d"):
		value = strings.TrimSuffix(p.curToken.Literal, "d")
		unit = 24 * time.Hour
	case strings.HasSuffix(p.curToken.Literal, "y"):
		value = strings.TrimSuffix(p.curToken.Literal, "y")
		unit = 365 * 24 * time.Hour
	default:
		return nil, errors.WithStack(TypeConversionError(p.curToken, "RTIME"))
	}

	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil, errors.WithStack(TypeConversionError(p.curToken, "RTIME"))
	}
	return &ast.RTime{
		Token:    p.curToken,
		Value:    p.curToken.Literal,
		Duration: time.Duration(int64(f * float64(unit))),
	}, nil
}

func (p *Parser) parsePrefixExpression() (ast.Expression, error) {
	exp := &ast.PrefixExpression{
		Token:    p.curToken,
		Operator: p.curToken.Literal,
	}

	p.nextToken()
	var err error
	exp.Right, err = p.parseExpression(PREFIX)
	if err != nil {
		return nil, err
	}

	return exp, nil
}

func (p *Parser) parseGroupedExpression() (ast.Expression, error) {
	exp := &ast.GroupedExpression{
		Token: p.curToken,
	}

	p.nextToken()
	var err error
	exp.Right, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, err
	}
	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	return exp, nil
}

// NOTE: On VCL, if expression syntax is defined like "if(cond, consequence, alternative)"
func (p *Parser) parseIfExpression() (ast.Expression, error) {
	exp := &ast.IfExpression{
		Token: p.curToken,
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
	// if expression is an expression so do not check trailing semicolon
	return exp, nil
}

func (p *Parser) parseIfStatement(args ...OptionFunc) (*ast.IfStatement, error) {
	arg := collect(args)
	exp := &ast.IfStatement{
		Comments:  arg.Comments,
		Token:     p.curToken,
		NestLevel: arg.NestLevel,
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
	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	exp.Consequence, err = p.parseBlockStatement(withNestLevel(arg.NestLevel + 1))
	if err != nil {
		return nil, err
	}
	// If statement may have some "else if" or "else" as another/alternative statement.
	// Note that before each statement, user could write comment
	for {
		comments := p.collectPeekComments(arg.NestLevel)
		switch p.peekToken.Type {
		case token.ELSE: // else
			p.nextToken()
			if p.peekTokenIs(token.IF) { // else if
				p.nextToken()
				another, err := p.parseAnotherIfStatement(withComments(comments), withNestLevel(arg.NestLevel))
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
			exp.Alternative, err = p.parseBlockStatement(withNestLevel(arg.NestLevel + 1))
			if err != nil {
				return nil, errors.WithStack(err)
			}
			goto FINISH
		case token.ELSEIF, token.ELSIF: // elseif, elsif
			p.nextToken()
			another, err := p.parseAnotherIfStatement(withComments(comments), withNestLevel(arg.NestLevel))
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
func (p *Parser) parseAnotherIfStatement(args ...OptionFunc) (*ast.IfStatement, error) {
	arg := collect(args)
	exp := &ast.IfStatement{
		Comments:  arg.Comments,
		Token:     p.curToken,
		NestLevel: arg.NestLevel,
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
	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	exp.Consequence, err = p.parseBlockStatement(withNestLevel(arg.NestLevel + 1))
	if err != nil {
		return nil, err
	}
	return exp, nil
}

func (p *Parser) parseInfixExpression(left ast.Expression) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Token:    p.curToken,
		Operator: p.curToken.Literal,
		Left:     left,
	}

	precedence := p.curPrecedence()
	p.nextToken()
	var err error
	exp.Right, err = p.parseExpression(precedence)
	if err != nil {
		return nil, err
	}

	return exp, nil
}

func (p *Parser) parseInfixStringConcatExpression(left ast.Expression) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Token:    p.curToken,
		Operator: "+",
		Left:     left,
	}

	precedence := p.curPrecedence()
	var err error
	exp.Right, err = p.parseExpression(precedence)
	if err != nil {
		return nil, err
	}

	return exp, nil
}

func (p *Parser) parseUnsetStatement(args ...OptionFunc) (*ast.UnsetStatement, error) {
	arg := collect(args)
	stmt := &ast.UnsetStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
	}
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	stmt.Ident = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	return stmt, nil
}

func (p *Parser) parseRemoveStatement(args ...OptionFunc) (*ast.RemoveStatement, error) {
	arg := collect(args)
	stmt := &ast.RemoveStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
	}
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	stmt.Ident = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	return stmt, nil
}

func (p *Parser) parseAddStatement(args ...OptionFunc) (*ast.AddStatement, error) {
	arg := collect(args)
	stmt := &ast.AddStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
	}
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	stmt.Ident = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
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
		return nil, err
	}
	stmt.Value = exp

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}
	return stmt, nil
}

func (p *Parser) parseEsiStatement(args ...OptionFunc) (*ast.EsiStatement, error) {
	arg := collect(args)
	stmt := &ast.EsiStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	return stmt, nil
}

func (p *Parser) parseRestartStatement(args ...OptionFunc) (*ast.RestartStatement, error) {
	arg := collect(args)
	stmt := &ast.RestartStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	return stmt, nil
}

func (p *Parser) parseCallStatement(args ...OptionFunc) (*ast.CallStatement, error) {
	arg := collect(args)
	stmt := &ast.CallStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
	}
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	stmt.Subroutine = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	return stmt, nil
}

func (p *Parser) parseDeclareStatement(args ...OptionFunc) (*ast.DeclareStatement, error) {
	arg := collect(args)
	stmt := &ast.DeclareStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
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
	stmt.Name = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.ValueType = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	return stmt, nil
}

func (p *Parser) parseErrorStatement(args ...OptionFunc) (*ast.ErrorStatement, error) {
	arg := collect(args)
	stmt := &ast.ErrorStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
	}

	// error code token must be ident or integer
	var err error
	switch p.peekToken.Type {
	case token.INT:
		p.nextToken()
		stmt.Code, err = p.parseInteger()
	case token.IDENT:
		p.nextToken()
		stmt.Code, err = p.parseIdent()
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

	return stmt, nil
}

func (p *Parser) parseLogStatement(args ...OptionFunc) (*ast.LogStatement, error) {
	arg := collect(args)
	stmt := &ast.LogStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
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

	return stmt, nil
}

func (p *Parser) parseReturnStatement(args ...OptionFunc) (*ast.ReturnStatement, error) {
	arg := collect(args)
	stmt := &ast.ReturnStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
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

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	stmt.Ident = &ast.Ident{
		Token: p.curToken,
		Value: p.curToken.Literal,
	}

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	if !p.expectPeek(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.peekToken))
	}

	return stmt, nil
}

func (p *Parser) parseSyntheticStatement(args ...OptionFunc) (*ast.SyntheticStatement, error) {
	arg := collect(args)
	stmt := &ast.SyntheticStatement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
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

	return stmt, nil
}

func (p *Parser) parseSyntheticBase64Statement(args ...OptionFunc) (*ast.SyntheticBase64Statement, error) {
	arg := collect(args)
	stmt := &ast.SyntheticBase64Statement{
		Token:     p.curToken,
		Comments:  arg.Comments,
		NestLevel: arg.NestLevel,
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

	return stmt, nil
}

func (p *Parser) parseFunctionCallExpression(fn ast.Expression) (ast.Expression, error) {
	exp := &ast.FunctionCallExpression{
		Token:    p.curToken,
		Function: fn,
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
