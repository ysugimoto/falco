package parser

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

func (p *Parser) parseImportStatement() (*ast.ImportStatement, error) {
	i := &ast.ImportStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	i.Name = p.parseIdent()

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	i.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return i, nil
}

func (p *Parser) parseIncludeStatement() (ast.Statement, error) {
	i := &ast.IncludeStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}
	i.Module = p.parseString()
	i.Meta.Trailing = p.trailing()

	// Semicolons are actually not required at the end of include lines
	// either works on fastly.
	if p.peekTokenIs(token.SEMICOLON) {
		p.nextToken() // point to SEMICOLON
	}

	return i, nil
}

func (p *Parser) parseBlockStatement() (*ast.BlockStatement, error) {
	// Note: block statement is used for declaration/statement inside like subroutine, if, elseif, else
	// on start this statement, current token must point start of LEFT_BRACE
	// and after on end this statement, current token must poinrt end of RIGHT_BRACE
	b := &ast.BlockStatement{
		Meta:       p.curToken,
		Statements: []ast.Statement{},
	}

	for !p.peekTokenIs(token.RIGHT_BRACE) {
		var stmt ast.Statement
		var err error

		p.nextToken() // point to statement
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
		case token.GOTO:
			stmt, err = p.parseGotoStatement()
		case token.IDENT:
			// Check if the current ident is a function call
			if p.peekTokenIs(token.LEFT_PAREN) {
				stmt, err = p.parseFunctionCall()
			} else {
				// Could be a goto destination
				stmt, err = p.parseGotoDestination()
			}
		default:
			err = UnexpectedToken(p.peekToken)
		}

		if err != nil {
			return nil, errors.WithStack(err)
		}
		b.Statements = append(b.Statements, stmt)
	}

	b.Meta.Trailing = p.trailing()
	p.nextToken() // point to RIGHT_BRACE

	// RIGHT_BRACE leading comments are block infix comments
	swapLeadingInfix(p.curToken, b.Meta)

	return b, nil
}

// nolint: dupl
func (p *Parser) parseSetStatement() (*ast.SetStatement, error) {
	stmt := &ast.SetStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.parseIdent()

	if !isAssignmentOperator(p.peekToken.Token) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, assignmentOperatorLiterals...))
	}
	p.nextToken() // point to assignment operator
	swapLeadingTrailing(p.curToken, stmt.Ident.Meta)

	stmt.Operator = &ast.Operator{
		Meta:     p.curToken,
		Operator: p.curToken.Token.Literal,
	}
	p.nextToken() // point to right expression start

	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = exp

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseUnsetStatement() (*ast.UnsetStatement, error) {
	stmt := &ast.UnsetStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.parseIdent()

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseRemoveStatement() (*ast.RemoveStatement, error) {
	stmt := &ast.RemoveStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.parseIdent()

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

// nolint: dupl
func (p *Parser) parseAddStatement() (*ast.AddStatement, error) {
	stmt := &ast.AddStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.parseIdent()

	if !isAssignmentOperator(p.peekToken.Token) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, assignmentOperatorLiterals...))
	}
	p.nextToken() // pojnt to assignment operator
	swapLeadingTrailing(p.curToken, stmt.Ident.Meta)

	stmt.Operator = &ast.Operator{
		Meta:     p.curToken,
		Operator: p.curToken.Token.Literal,
	}
	p.nextToken() // start expression token

	exp, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = exp

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseCallStatement() (*ast.CallStatement, error) {
	stmt := &ast.CallStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Subroutine = p.parseIdent()

	// Parse functions with ()
	if p.peekTokenIs(token.LEFT_PAREN) {
		p.nextToken() // point to the token to check if it is RIGHT_PAREN
		if !p.peekTokenIs(token.RIGHT_PAREN) {
			return nil, errors.WithStack(UnexpectedToken(p.curToken))
		}
		p.nextToken() // point to RIGHT_PAREN
	}

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseDeclareStatement() (*ast.DeclareStatement, error) {
	stmt := &ast.DeclareStatement{
		Meta: p.curToken,
	}

	// Declare Syntax is declare [IDENT:"local"] [IDENT:variable name] [IDENT:VCL type]
	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	if p.curToken.Token.Literal != "local" {
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

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseErrorStatement() (*ast.ErrorStatement, error) {
	stmt := &ast.ErrorStatement{
		Meta: p.curToken,
	}

	// error code token must be ident or integer
	var err error
	switch p.peekToken.Token.Type {
	case token.INT:
		p.nextToken()
		stmt.Code, err = p.parseInteger()
	case token.IDENT:
		p.nextToken()
		if p.peekTokenIs(token.LEFT_PAREN) {
			i := p.parseIdent()
			p.nextToken()
			stmt.Code, err = p.parseFunctionCallExpression(i)
		} else {
			stmt.Code = p.parseIdent()
		}
	default:
		err = UnexpectedToken(p.peekToken)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Optional expression, error statement argument
	if !p.peekTokenIs(token.SEMICOLON) {
		p.nextToken()
		stmt.Argument, err = p.parseExpression(LOWEST)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseEsiStatement() (*ast.EsiStatement, error) {
	stmt := &ast.EsiStatement{
		Meta: p.curToken,
	}

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseLogStatement() (*ast.LogStatement, error) {
	stmt := &ast.LogStatement{
		Meta: p.curToken,
	}

	p.nextToken() // point to log value expression
	value, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = value

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseRestartStatement() (*ast.RestartStatement, error) {
	stmt := &ast.RestartStatement{
		Meta: p.curToken,
	}

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseReturnStatement() (*ast.ReturnStatement, error) {
	stmt := &ast.ReturnStatement{
		Meta:           p.curToken,
		HasParenthesis: false,
	}

	// return statement may not have argument
	// https://developer.fastly.com/reference/vcl/statements/return/
	if p.peekTokenIs(token.SEMICOLON) {
		stmt.Meta.Trailing = p.trailing()
		p.nextToken() // point to SEMICOLON
		return stmt, nil
	}

	hasLeftParen := p.peekTokenIs(token.LEFT_PAREN)
	if hasLeftParen {
		stmt.HasParenthesis = true
		p.nextToken() // point to expression
	}
	p.nextToken()

	expression, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.ReturnExpression = &expression

	hasRightParen := p.peekTokenIs(token.RIGHT_PAREN)
	if hasRightParen {
		p.nextToken() // point to condition expression
	}
	if hasLeftParen != hasRightParen {
		return nil, errors.WithStack(&ParseError{
			Token:   p.curToken.Token,
			Message: "Parenthesis missmatch",
		})
	}

	swapLeadingTrailing(p.curToken, (*stmt.ReturnExpression).GetMeta())

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseSyntheticStatement() (*ast.SyntheticStatement, error) {
	stmt := &ast.SyntheticStatement{
		Meta: p.curToken,
	}

	p.nextToken() // point to synthetic value expression
	value, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = value

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseSyntheticBase64Statement() (*ast.SyntheticBase64Statement, error) {
	stmt := &ast.SyntheticBase64Statement{
		Meta: p.curToken,
	}

	p.nextToken()
	value, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = value

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

// nolint: gocognit
func (p *Parser) parseIfStatement() (*ast.IfStatement, error) {
	stmt := &ast.IfStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}

	p.nextToken() // point to condition expression
	cond, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Condition = cond

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	// parse Consequence block
	stmt.Consequence, err = p.parseBlockStatement()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// cursor must be on RIGHT_BRACE

	// If statement may have some "else if" or "else" as another/alternative statement
	for {
		switch p.peekToken.Token.Type {
		case token.ELSE: // else
			p.nextToken() // point to ELSE

			// If more peek token is IF, it should be "else if"
			if p.peekTokenIs(token.IF) { // else if
				p.nextToken() // point to IF
				another, err := p.parseAnotherIfStatement()
				if err != nil {
					return nil, errors.WithStack(err)
				}
				stmt.Another = append(stmt.Another, another)
				continue
			}

			// Otherwise, it is else statement. next token must be LEFT_BRACE
			if !p.expectPeek(token.LEFT_BRACE) {
				return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
			}
			stmt.Alternative, err = p.parseBlockStatement()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			// exit for loop
			goto FINISH
		// Note: VCL could define "else if" statement with "elseif", "elsif" keyword
		case token.ELSEIF, token.ELSIF: // elseif, elsif
			p.nextToken() // point to ELSEIF/ELSIF
			another, err := p.parseAnotherIfStatement()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			stmt.Another = append(stmt.Another, another)
			continue
		}
		// If not match, if statement does not have another/alternative statement
		goto FINISH
	}
FINISH:
	return stmt, nil
}

// AnotherIfStatement is similar to IfStatement but is not culious about alternative.
func (p *Parser) parseAnotherIfStatement() (*ast.IfStatement, error) {
	stmt := &ast.IfStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}

	p.nextToken() // point to condition expression
	cond, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Condition = cond

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	if !p.expectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	// parse Consequence block
	stmt.Consequence, err = p.parseBlockStatement()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// cursor must be on RIGHT_BRACE
	return stmt, nil
}

func (p *Parser) parseGotoStatement() (*ast.GotoStatement, error) {
	stmt := &ast.GotoStatement{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Destination = p.parseIdent()

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}

func (p *Parser) parseGotoDestination() (*ast.GotoDestinationStatement, error) {
	if !isGotoDestination(p.curToken.Token) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	stmt := &ast.GotoDestinationStatement{
		Meta: p.curToken,
	}
	stmt.Name = p.parseIdent()
	stmt.Meta.Trailing = p.trailing()

	return stmt, nil
}

func (p *Parser) parseFunctionCall() (*ast.FunctionCallStatement, error) {
	stmt := &ast.FunctionCallStatement{
		Meta:     p.curToken,
		Function: p.parseIdent(),
	}

	p.nextToken() // point to LEFT_PAREN
	args, err := p.parseFunctionArgumentExpressions()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Arguments = args

	if !p.peekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	stmt.Meta.Trailing = p.trailing()
	p.nextToken() // point to SEMICOLON

	return stmt, nil
}
