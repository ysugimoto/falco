package parser

import (
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

	prevToken *ast.Meta
	curToken  *ast.Meta
	peekToken *ast.Meta
	level     int

	prefixParsers map[token.TokenType]prefixParser
	infixParsers  map[token.TokenType]infixParser
}

func New(l *lexer.Lexer) *Parser {
	p := &Parser{
		l: l,
	}

	p.registerExpressionParsers()

	p.nextToken()
	p.nextToken()

	return p
}

func (p *Parser) nextToken() {
	p.prevToken = p.curToken
	p.curToken = p.peekToken

	p.readPeek()
}

func (p *Parser) readPeek() {
	leading := ast.Comments{}
	for {
		t := p.l.NextToken()
		switch t.Type {
		case token.LF:
			continue
		case token.COMMENT:
			leading = append(leading, &ast.Comment{
				Token: t,
				Value: t.Literal,
			})
			continue
		case token.LEFT_BRACE:
			p.level++
		case token.RIGHT_BRACE:
			p.level--
		}
		p.peekToken = ast.New(t, p.level, leading)
		break
	}
}

func (p *Parser) trailing() ast.Comments {
	cs := ast.Comments{}
	for {
		// Analyze peek token
		tok := p.l.PeekToken()
		if tok.Type == token.LF {
			break
		}
		if tok.Type == token.EOF {
			return cs
		}
		if tok.Type == token.COMMENT {
			cs = append(cs, &ast.Comment{
				Token: tok,
				Value: tok.Literal,
			})
			// advance token
			p.l.NextToken()
			continue
		}
		break
	}

	return cs
}

func (p *Parser) curTokenIs(t token.TokenType) bool {
	return p.curToken.Token.Type == t
}

func (p *Parser) peekTokenIs(t token.TokenType) bool {
	return p.peekToken.Token.Type == t
}

func (p *Parser) expectPeek(t token.TokenType) bool {
	if !p.peekTokenIs(t) {
		return false
	}
	p.nextToken()
	return true
}

func (p *Parser) curPrecedence() int {
	if v, ok := precedences[p.curToken.Token.Type]; ok {
		return v
	}
	return LOWEST
}

func (p *Parser) peekPrecedence() int {
	if v, ok := precedences[p.peekToken.Token.Type]; ok {
		return v
	}
	return LOWEST
}

// ParseVCL parses main VCL
func (p *Parser) ParseVCL() (*ast.VCL, error) {
	vcl := &ast.VCL{}

	for !p.curTokenIs(token.EOF) {
		stmt, err := p.parse()
		if err != nil {
			return nil, err
		} else if stmt != nil {
			vcl.Statements = append(vcl.Statements, stmt)
		}
	}

	return vcl, nil
}

// ParseStatement parses included VCL.
// In "include" statement, process read partial an VCL (file or snippet, regular or dynamic),
// but the partial VCL may not be used in root VCL, can be used inside subroutine.
// Then we need to parse them as inline statement, e.g:
//
// #main.vcl
// include "module"; // <- valid, read and parse as ParseVCL()
// ...
// sub foo_recv {
//   include "snippet::some_module"; // valid, need to parse by ParseStatement()
//   include "statement-module";     // valid, need to parse by ParseStatement()
// }
func (p *Parser) ParseStatement() ([]ast.Statement, error) {
	var statements []ast.Statement

	for !p.curTokenIs(token.EOF) {
		var stmt ast.Statement
		var err error

		switch p.curToken.Token.Type {
		// https://github.com/ysugimoto/falco/issues/17
		// VCL accepts block syntax:
		// ```
		// sub vcl_recv {
		//   {
		//      log "recv";
		//   }
		// }
		// ```
		case token.LEFT_BRACE:
			stmt, err = p.parseBlockStatement()
		case token.SET:
			stmt, err = p.parseSetStatement()
		case token.UNSET:
			stmt, err = p.parseUnsetStatement()
		case token.REMOVE:
			stmt, err = p.parseRemoveStatement()
		case token.ADD:
			stmt, err = p.parseAddStatement()
		case token.CALL:
			stmt, err = p.parseCallStatement()
		case token.DECLARE:
			stmt, err = p.parseDeclareStatement()
		case token.ERROR:
			stmt, err = p.parseErrorStatement()
		case token.ESI:
			stmt, err = p.parseEsiStatement()
		case token.LOG:
			stmt, err = p.parseLogStatement()
		case token.RESTART:
			stmt, err = p.parseRestartStatement()
		case token.RETURN:
			stmt, err = p.parseReturnStatement()
		case token.SYNTHETIC:
			stmt, err = p.parseSyntheticStatement()
		case token.SYNTHETIC_BASE64:
			stmt, err = p.parseSyntheticBase64Statement()
		case token.IF:
			stmt, err = p.parseIfStatement()
		default:
			err = UnexpectedToken(p.peekToken)
		}

		if err != nil {
			return nil, errors.WithStack(err)
		}
		statements = append(statements, stmt)
		p.nextToken()
	}

	return statements, nil
}

func (p *Parser) parse() (ast.Statement, error) {
	var stmt ast.Statement
	var err error

	switch p.curToken.Token.Type {
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
