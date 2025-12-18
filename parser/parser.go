package parser

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

// Reference: https://developer.fastly.com/reference/vcl/operators/
const (
	LOWEST int = iota + 1
	OR
	AND
	REGEX
	EQUALS
	LESS_GREATER
	CONCAT
	PREFIX
	POSTFIX
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
	token.OPEN_LONG_STRING:   CONCAT,
	token.IDENT:              CONCAT,
	token.IF:                 CONCAT,
	token.LEFT_PAREN:         CALL,
	token.AND:                AND,
	token.OR:                 OR,
	token.PERCENT:            POSTFIX,
}

type (
	prefixParser  func() (ast.Expression, error)
	infixParser   func(ast.Expression) (ast.Expression, error)
	postfixParser func(ast.Expression) (ast.Expression, error)
)

type Tokenizer interface {
	NextToken() token.Token
	PeekToken() token.Token
	RegisterCustomTokens(map[string]token.TokenType)
}

type Parser struct {
	tk Tokenizer

	prevToken *ast.Meta
	curToken  *ast.Meta
	peekToken *ast.Meta
	level     int

	prefixParsers  map[token.TokenType]prefixParser
	infixParsers   map[token.TokenType]infixParser
	postfixParsers map[token.TokenType]postfixParser
	customParsers  map[token.TokenType]CustomParser
}

func New(tk Tokenizer, opts ...ParserOption) *Parser {
	p := &Parser{
		tk:            tk,
		customParsers: make(map[token.TokenType]CustomParser),
	}
	for i := range opts {
		opts[i](p)
	}

	p.registerExpressionParsers()

	// Register custom lexer tokens for each custom parsers
	customTokenMap := make(map[string]token.TokenType)
	for _, v := range p.customParsers {
		customTokenMap[v.Ident()] = v.Token()
	}
	tk.RegisterCustomTokens(customTokenMap)

	p.NextToken()
	p.NextToken()

	return p
}

func (p *Parser) NextToken() {
	p.prevToken = p.curToken
	p.curToken = p.peekToken

	p.ReadPeek()
}

func (p *Parser) ReadPeek() {
	leading := ast.Comments{}
	var prefixedLineFeed bool
	var previousEmptyLines int

	for {
		t := p.tk.NextToken()
		switch t.Type {
		case token.LF:
			prefixedLineFeed = true
			// Count empty lines between the next token
			for {
				peek := p.tk.PeekToken()
				if peek.Type != token.LF {
					break
				}
				previousEmptyLines++
				p.tk.NextToken()
			}
			continue
		case token.COMMENT:
			leading = append(leading, &ast.Comment{
				Token:              t,
				Value:              t.Literal,
				PrefixedLineFeed:   prefixedLineFeed,
				PreviousEmptyLines: previousEmptyLines,
			})
			previousEmptyLines = 0
			continue
		case token.LEFT_BRACE:
			p.level++
		case token.RIGHT_BRACE:
			p.level--
		case token.FASTLY_CONTROL:
			// Skip Fastly control syntaxes
			continue
		case token.PRAGMA:
			// Skip Fastly pgrama embedded data
			for {
				t = p.tk.NextToken()
				if t.Type == token.SEMICOLON {
					break
				}
			}
			continue
		}
		meta := ast.New(t, p.level, leading)
		meta.PreviousEmptyLines = previousEmptyLines
		p.peekToken = meta
		break
	}
}

func (p *Parser) Trailing() ast.Comments {
	cs := ast.Comments{}

	// Divide trailing comment for current node and leading comment for next node
	if len(p.peekToken.Leading) > 0 {
		updated := []*ast.Comment{}
		for i, l := range p.peekToken.Leading {
			if l.PrefixedLineFeed {
				updated = p.peekToken.Leading[i:]
				break
			}
			cs = append(cs, p.peekToken.Leading[i])
		}
		p.peekToken.Leading = updated
	}
	return cs
}

func (p *Parser) PeekToken() *ast.Meta {
	return p.peekToken
}

func (p *Parser) CurToken() *ast.Meta {
	return p.curToken
}

func (p *Parser) PrevTokenIs(t token.TokenType) bool {
	return p.prevToken.Token.Type == t
}

func (p *Parser) CurTokenIs(t token.TokenType) bool {
	return p.curToken.Token.Type == t
}

func (p *Parser) PeekTokenIs(t token.TokenType) bool {
	return p.peekToken.Token.Type == t
}

func (p *Parser) ExpectPeek(t token.TokenType) bool {
	if !p.PeekTokenIs(t) {
		return false
	}
	p.NextToken()
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

// isDeclarationToken checks if the token type is a top-level declaration keyword
func (p *Parser) isDeclarationToken(t token.TokenType) bool {
	switch t {
	case token.ACL, token.IMPORT, token.INCLUDE, token.BACKEND,
		token.DIRECTOR, token.TABLE, token.SUBROUTINE,
		token.PENALTYBOX, token.RATECOUNTER:
		return true
	default:
		// Check custom parsers
		_, ok := p.customParsers[t]
		return ok
	}
}

// ParseVCLOrSnippet determines whether to parse as full VCL or as a snippet.
// If the first non-comment token is not a declaration, treat it as a snippet.
// Returns the parsed VCL and whether it was parsed as a snippet.
func (p *Parser) ParseVCLOrSnippet() (*ast.VCL, error) {
	// Check if first token is a declaration keyword
	if p.isDeclarationToken(p.curToken.Token.Type) || p.CurTokenIs(token.EOF) {
		return p.ParseVCL()
	}

	// Parse as snippet - the file contains statements, not declarations
	statements, err := p.ParseSnippetVCL()
	if err != nil {
		return nil, err
	}

	// Return VCL with snippet flag set
	vcl := &ast.VCL{
		Statements: make([]ast.Statement, len(statements)),
		IsSnippet:  true,
	}
	for i, s := range statements {
		vcl.Statements[i] = s
	}
	return vcl, nil
}

func (p *Parser) ParseVCL() (*ast.VCL, error) {
	vcl := &ast.VCL{}

	for !p.CurTokenIs(token.EOF) {
		stmt, err := p.Parse()
		if err != nil {
			return nil, err
		} else if stmt != nil {
			vcl.Statements = append(vcl.Statements, stmt)
		}
	}

	return vcl, nil
}

func (p *Parser) Parse() (ast.Statement, error) {
	var stmt ast.Statement
	var err error

	switch p.curToken.Token.Type {
	case token.ACL:
		stmt, err = p.ParseAclDeclaration()
	case token.IMPORT:
		stmt, err = p.ParseImportStatement()
	case token.INCLUDE:
		stmt, err = p.ParseIncludeStatement()
	case token.BACKEND:
		stmt, err = p.ParseBackendDeclaration()
	case token.DIRECTOR:
		stmt, err = p.ParseDirectorDeclaration()
	case token.TABLE:
		stmt, err = p.ParseTableDeclaration()
	case token.SUBROUTINE:
		stmt, err = p.ParseSubroutineDeclaration()
	case token.PENALTYBOX:
		stmt, err = p.ParsePenaltyboxDeclaration()
	case token.RATECOUNTER:
		stmt, err = p.ParseRatecounterDeclaration()
	default:
		if custom, ok := p.customParsers[p.curToken.Token.Type]; ok {
			stmt, err = custom.Parse(p)
		} else {
			err = UnexpectedToken(p.curToken)
		}
	}

	if err != nil {
		return nil, errors.WithStack(err)
	}
	p.NextToken()
	return stmt, nil
}

// ParseSnippetVCL is used for snippet parsing.
// VCL snippet is a piece of vcl code so we should Parse like BlockStatement inside,
// and returns slice of statement.
func (p *Parser) ParseSnippetVCL() ([]ast.Statement, error) {
	var statements []ast.Statement

	for !p.PeekTokenIs(token.EOF) {
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
			stmt, err = p.ParseBlockStatement()
		case token.SET:
			stmt, err = p.ParseSetStatement()
		case token.UNSET:
			stmt, err = p.ParseUnsetStatement()
		case token.REMOVE:
			stmt, err = p.ParseRemoveStatement()
		case token.ADD:
			stmt, err = p.ParseAddStatement()
		case token.CALL:
			stmt, err = p.ParseCallStatement()
		case token.DECLARE:
			stmt, err = p.ParseDeclareStatement()
		case token.ERROR:
			stmt, err = p.ParseErrorStatement()
		case token.ESI:
			stmt, err = p.ParseEsiStatement()
		case token.LOG:
			stmt, err = p.ParseLogStatement()
		case token.RESTART:
			stmt, err = p.ParseRestartStatement()
		case token.RETURN:
			stmt, err = p.ParseReturnStatement()
		case token.SYNTHETIC:
			stmt, err = p.ParseSyntheticStatement()
		case token.SYNTHETIC_BASE64:
			stmt, err = p.ParseSyntheticBase64Statement()
		case token.IF:
			stmt, err = p.ParseIfStatement()
		case token.GOTO:
			stmt, err = p.ParseGotoStatement()
		case token.INCLUDE:
			stmt, err = p.ParseIncludeStatement()
		case token.IDENT:
			// Check if the current ident is a function call
			if p.PeekTokenIs(token.LEFT_PAREN) {
				stmt, err = p.ParseFunctionCall()
			} else {
				// Could be a goto destination
				stmt, err = p.ParseGotoDestination()
			}
		default:
			err = UnexpectedToken(p.peekToken)
		}

		if err != nil {
			return nil, errors.WithStack(err)
		}
		statements = append(statements, stmt)
		p.NextToken() // point to statement
	}

	p.NextToken() // point to EOF
	return statements, nil
}
