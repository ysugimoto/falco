package parser

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

func (p *Parser) ParseStatement() (ast.Statement, error) {
	var stmt ast.Statement
	var err error

	p.NextToken() // point to statement
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
	case token.SWITCH:
		stmt, err = p.ParseSwitchStatement()
	case token.GOTO:
		stmt, err = p.ParseGotoStatement()
	case token.INCLUDE:
		stmt, err = p.ParseIncludeStatement()
	case token.BREAK:
		stmt, err = p.ParseBreakStatement()
	case token.FALLTHROUGH:
		stmt, err = p.ParseFallthroughStatement()
	case token.IDENT:
		// Check if the current ident is a function call
		if p.PeekTokenIs(token.LEFT_PAREN) {
			stmt, err = p.ParseFunctionCall()
		} else {
			// Could be a goto destination
			stmt, err = p.ParseGotoDestination()
			if err != nil {
				// raise an error on the current token
				err = UnexpectedToken(p.curToken)
			}
		}
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
	return stmt, nil
}

func (p *Parser) ParseImportStatement() (*ast.ImportStatement, error) {
	i := &ast.ImportStatement{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	i.Name = p.ParseIdent()

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	i.Meta.EndLine = i.Name.EndLine
	i.Meta.EndPosition = i.Name.EndPosition
	p.NextToken() // point to SEMICOLON
	SwapLeadingTrailing(p.curToken, i.Name.Meta)
	i.Meta.Trailing = p.Trailing()

	return i, nil
}

func (p *Parser) ParseIncludeStatement() (ast.Statement, error) {
	i := &ast.IncludeStatement{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.STRING) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "STRING"))
	}
	var err error
	i.Module, err = p.ParseString()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Semicolons are actually not required at the end of include lines
	// either works on fastly.
	if p.PeekTokenIs(token.SEMICOLON) {
		p.NextToken() // point to SEMICOLON
		SwapLeadingTrailing(p.curToken, i.Module.Meta)
	}
	i.Meta.Trailing = p.Trailing()
	i.Meta.EndLine = i.Module.EndLine
	i.Meta.EndPosition = i.Module.EndPosition

	return i, nil
}

func (p *Parser) ParseBlockStatement() (*ast.BlockStatement, error) {
	// Note: block statement is used for declaration/statement inside like subroutine, if, elseif, else
	// on start this statement, current token must point start of LEFT_BRACE
	// and after on end this statement, current token must point end of RIGHT_BRACE
	b := &ast.BlockStatement{
		Meta:       p.curToken,
		Statements: []ast.Statement{},
	}

	for !p.PeekTokenIs(token.RIGHT_BRACE) {
		stmt, err := p.ParseStatement()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		switch stmt.(type) {
		case *ast.BreakStatement, *ast.FallthroughStatement:
			return nil, UnexpectedToken(stmt.GetMeta())
		}
		b.Statements = append(b.Statements, stmt)
	}

	p.NextToken() // point to RIGHT_BRACE
	b.Meta.Trailing = p.Trailing()
	b.Meta.EndLine = p.curToken.Token.Line
	b.Meta.EndPosition = p.curToken.Token.Position

	// RIGHT_BRACE leading comments are block infix comments
	SwapLeadingInfix(p.curToken, b.Meta)

	return b, nil
}

func (p *Parser) ParseSetStatement() (*ast.SetStatement, error) {
	stmt := &ast.SetStatement{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.ParseIdent()

	if !isAssignmentOperator(p.peekToken.Token) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, assignmentOperatorLiterals...))
	}
	p.NextToken() // point to assignment operator
	SwapLeadingTrailing(p.curToken, stmt.Ident.Meta)

	stmt.Operator = &ast.Operator{
		Meta:     p.curToken,
		Operator: p.curToken.Token.Literal,
	}
	stmt.Operator.Meta.EndLine = p.curToken.Token.Line
	stmt.Operator.Meta.EndPosition = p.curToken.Token.Position + len(p.curToken.Token.Literal) - 1

	p.NextToken() // point to right expression start

	exp, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = exp

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.EndLine = exp.GetMeta().EndLine
	stmt.Meta.EndPosition = exp.GetMeta().EndPosition

	p.NextToken() // point to SEMICOLON
	SwapLeadingTrailing(p.curToken, stmt.Value.GetMeta())
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseUnsetStatement() (*ast.UnsetStatement, error) {
	stmt := &ast.UnsetStatement{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.ParseIdent()

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	SwapLeadingTrailing(p.curToken, stmt.Ident.GetMeta())
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseRemoveStatement() (*ast.RemoveStatement, error) {
	stmt := &ast.RemoveStatement{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.ParseIdent()

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	SwapLeadingTrailing(p.curToken, stmt.Ident.GetMeta())
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseAddStatement() (*ast.AddStatement, error) {
	stmt := &ast.AddStatement{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Ident = p.ParseIdent()

	if !isAssignmentOperator(p.peekToken.Token) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, assignmentOperatorLiterals...))
	}
	p.NextToken() // pojnt to assignment operator
	SwapLeadingTrailing(p.curToken, stmt.Ident.Meta)

	stmt.Operator = &ast.Operator{
		Meta:     p.curToken,
		Operator: p.curToken.Token.Literal,
	}
	p.NextToken() // start expression token

	exp, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = exp

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	SwapLeadingTrailing(p.curToken, stmt.Value.GetMeta())
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseCallStatement() (*ast.CallStatement, error) {
	stmt := &ast.CallStatement{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Subroutine = p.ParseIdent()

	// Parse functions with ()
	if p.PeekTokenIs(token.LEFT_PAREN) {
		p.NextToken() // point to the token to check if it is RIGHT_PAREN
		if !p.PeekTokenIs(token.RIGHT_PAREN) {
			return nil, errors.WithStack(UnexpectedToken(p.curToken))
		}
		p.NextToken() // point to RIGHT_PAREN
	}

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	p.NextToken() // point to SEMICOLON
	SwapLeadingTrailing(p.curToken, stmt.Subroutine.GetMeta())
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseDeclareStatement() (*ast.DeclareStatement, error) {
	stmt := &ast.DeclareStatement{
		Meta: p.curToken,
	}

	// Declare Syntax is declare [IDENT:"local"] [IDENT:variable name] [IDENT:VCL type]
	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	if p.curToken.Token.Literal != "local" {
		return nil, errors.WithStack(UnexpectedToken(p.curToken, "local"))
	}
	SwapLeadingInfix(p.curToken, stmt.Meta)

	// Variable Name
	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Name = p.ParseIdent()

	// Variable Type
	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	SwapLeadingTrailing(p.curToken, stmt.Name.Meta)
	stmt.ValueType = p.ParseIdent()

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	SwapLeadingTrailing(p.curToken, stmt.ValueType.Meta)
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseErrorStatement() (*ast.ErrorStatement, error) {
	stmt := &ast.ErrorStatement{
		Meta: p.curToken,
	}

	// error code token must be ident or integer
	var err error
	switch p.peekToken.Token.Type {
	case token.INT:
		p.NextToken()
		stmt.Code, err = p.ParseInteger()
	case token.IDENT:
		p.NextToken()
		if p.PeekTokenIs(token.LEFT_PAREN) {
			i := p.ParseIdent()
			p.NextToken()
			stmt.Code, err = p.ParseFunctionCallExpression(i)
		} else {
			stmt.Code = p.ParseIdent()
		}
	case token.SEMICOLON: // without code and response like "error;"
		break
	default:
		err = UnexpectedToken(p.peekToken)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Optional expression, error statement argument
	if !p.PeekTokenIs(token.SEMICOLON) {
		p.NextToken()
		stmt.Argument, err = p.ParseExpression(LOWEST)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	// Calculate end line and position
	switch {
	case stmt.Argument != nil:
		stmt.Meta.EndLine = stmt.Argument.GetMeta().EndLine
		stmt.Meta.EndPosition = stmt.Argument.GetMeta().EndPosition
	case stmt.Code != nil:
		stmt.Meta.EndLine = stmt.Code.GetMeta().EndLine
		stmt.Meta.EndPosition = stmt.Code.GetMeta().EndPosition
	default:
		stmt.Meta.EndLine = stmt.GetMeta().Token.Line
		stmt.Meta.EndPosition = stmt.GetMeta().Token.Position + len(stmt.GetMeta().Token.Literal) - 1
	}

	p.NextToken() // point to SEMICOLON

	switch {
	// If argument exists, attach comment to it as Trailing
	case stmt.Argument != nil:
		SwapLeadingTrailing(p.curToken, stmt.Argument.GetMeta())
	// If code exists, attach comment to it as Trailing
	case stmt.Code != nil:
		SwapLeadingTrailing(p.curToken, stmt.Code.GetMeta())
	// Otherwise, attach comment to the statement as Trailing
	default:
		SwapLeadingTrailing(p.curToken, stmt.Meta)
	}
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseEsiStatement() (*ast.EsiStatement, error) {
	stmt := &ast.EsiStatement{
		Meta: p.curToken,
	}

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	SwapLeadingInfix(p.curToken, stmt.Meta)
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseLogStatement() (*ast.LogStatement, error) {
	stmt := &ast.LogStatement{
		Meta: p.curToken,
	}

	p.NextToken() // point to log value expression
	value, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = value

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseRestartStatement() (*ast.RestartStatement, error) {
	stmt := &ast.RestartStatement{
		Meta: p.curToken,
	}

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	stmt.Meta.EndLine = p.curToken.Token.Line
	stmt.Meta.EndPosition = p.curToken.Token.Position + 6 // point "t" position of "restart" characters
	p.NextToken()                                         // point to SEMICOLON
	SwapLeadingInfix(p.curToken, stmt.Meta)
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseReturnStatement() (*ast.ReturnStatement, error) {
	stmt := &ast.ReturnStatement{
		Meta:                        p.curToken,
		HasParenthesis:              false,
		ParenthesisLeadingComments:  ast.Comments{},
		ParenthesisTrailingComments: ast.Comments{},
	}

	// return statement may not have argument
	// https://developer.fastly.com/reference/vcl/statements/return/
	if p.PeekTokenIs(token.SEMICOLON) {
		p.NextToken() // point to SEMICOLON
		SwapLeadingInfix(p.curToken, stmt.Meta)
		stmt.Meta.Trailing = p.Trailing()
		return stmt, nil
	}

	hasLeftParen := p.PeekTokenIs(token.LEFT_PAREN)
	if hasLeftParen {
		stmt.HasParenthesis = true
		p.NextToken() // point to left parenthesis
		stmt.ParenthesisLeadingComments = p.curToken.Leading
	}
	p.NextToken() // point to expression

	expression, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.ReturnExpression = expression

	hasRightParen := p.PeekTokenIs(token.RIGHT_PAREN)
	if hasRightParen {
		p.NextToken() // point to right parenthesis
		SwapLeadingTrailing(p.curToken, stmt.ReturnExpression.GetMeta())
	}
	if hasLeftParen != hasRightParen {
		return nil, errors.WithStack(&ParseError{
			Token:   p.curToken.Token,
			Message: "Parenthesis mismatch",
		})
	}

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	if hasRightParen {
		stmt.ParenthesisTrailingComments = p.curToken.Leading
	} else {
		SwapLeadingTrailing(p.curToken, stmt.ReturnExpression.GetMeta())
	}
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseSyntheticStatement() (*ast.SyntheticStatement, error) {
	stmt := &ast.SyntheticStatement{
		Meta: p.curToken,
	}

	p.NextToken() // point to synthetic value expression
	value, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = value

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseSyntheticBase64Statement() (*ast.SyntheticBase64Statement, error) {
	stmt := &ast.SyntheticBase64Statement{
		Meta: p.curToken,
	}

	p.NextToken()
	value, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Value = value

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseIfStatement() (*ast.IfStatement, error) {
	stmt := &ast.IfStatement{
		Keyword: "if",
		Meta:    p.curToken,
	}

	if !p.ExpectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}
	SwapLeadingInfix(p.curToken, stmt.Meta)

	p.NextToken() // point to condition expression
	cond, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Condition = cond

	if !p.ExpectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	SwapLeadingTrailing(p.curToken, stmt.Condition.GetMeta())

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	// Parse Consequence block
	stmt.Consequence, err = p.ParseBlockStatement()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// cursor must be on RIGHT_BRACE

	// If statement may have some "else if" or "else" as another/alternative statement
	for {
		switch p.peekToken.Token.Type {
		case token.ELSE: // else
			p.NextToken() // point to ELSE

			// If more peek token is IF, it should be "else if"
			if p.PeekTokenIs(token.IF) { // else if
				// The leading comment of else if node is exists in "ELSE" token
				// so store the comment before forward token
				leading := p.curToken.Leading

				p.NextToken() // point to IF
				another, err := p.ParseAnotherIfStatement("else if")
				if err != nil {
					return nil, errors.WithStack(err)
				}
				// And restore the leading comments
				another.Leading = leading

				stmt.Another = append(stmt.Another, another)
				continue
			}

			// Otherwise, it is else statement
			alternative := &ast.ElseStatement{
				Meta: p.curToken,
			}
			// Next token must be LEFT_BRACE
			if !p.ExpectPeek(token.LEFT_BRACE) {
				return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
			}
			SwapLeadingInfix(p.curToken, alternative.Meta)
			alternative.Consequence, err = p.ParseBlockStatement()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			alternative.Meta.EndLine = p.curToken.Token.Line
			alternative.Meta.EndPosition = p.curToken.Token.Position
			stmt.Alternative = alternative
			// exit for loop
			goto FINISH
		// Note: VCL could define "else if" statement with "elseif", "elsif" keyword
		case token.ELSEIF, token.ELSIF: // elseif, elsif
			p.NextToken() // point to ELSEIF/ELSIF
			another, err := p.ParseAnotherIfStatement(p.curToken.Token.Literal)
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
	stmt.Meta.Trailing = p.Trailing()
	stmt.Meta.EndLine = p.curToken.Token.Line
	stmt.Meta.EndPosition = p.curToken.Token.Position
	return stmt, nil
}

// AnotherIfStatement is similar to IfStatement but is not culious about alternative.
func (p *Parser) ParseAnotherIfStatement(keyword string) (*ast.IfStatement, error) {
	stmt := &ast.IfStatement{
		Keyword: keyword,
		Meta:    p.curToken,
	}

	if !p.ExpectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}
	SwapLeadingInfix(p.curToken, stmt.Meta)

	p.NextToken() // point to condition expression
	cond, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Condition = cond

	if !p.ExpectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	SwapLeadingTrailing(p.curToken, stmt.Condition.GetMeta())

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}

	// Parse Consequence block
	stmt.Consequence, err = p.ParseBlockStatement()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// cursor must be on RIGHT_BRACE
	stmt.Meta.EndLine = p.curToken.Token.Line
	stmt.Meta.EndPosition = p.curToken.Token.Position
	return stmt, nil
}

func (p *Parser) ParseSwitchStatement() (*ast.SwitchStatement, error) {
	stmt := &ast.SwitchStatement{
		Meta:    p.curToken,
		Default: -1, // -1 is used to represent a switch without a default case.
	}

	if !p.ExpectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}

	control := &ast.SwitchControl{
		Meta: p.curToken,
	}

	p.NextToken() // point at control expression

	// Switch control expression can be a literal, variable identifier, or
	// function call.
	var err error
	if p.PeekTokenIs(token.LEFT_PAREN) {
		i := p.ParseIdent()
		p.NextToken()
		control.Expression, err = p.ParseFunctionCallExpression(i)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	} else {
		if p.CurTokenIs(token.IDENT) {
			control.Expression = p.ParseIdent()
		} else {
			// Only string and bool literals can be used as a switch control
			// expression.
			if !p.CurTokenIs(token.TRUE) && !p.CurTokenIs(token.FALSE) && !p.CurTokenIs(token.STRING) {
				return nil, UnexpectedToken(
					p.curToken,
					"invalid literal %s for switch control, expect BOOL or STRING",
					string(p.curToken.Token.Type))
			}
			control.Expression, err = p.ParseExpression(LOWEST)
			if err != nil {
				return nil, errors.WithStack(err)
			}
		}
	}

	if !p.ExpectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	SwapLeadingTrailing(p.curToken, control.Expression.GetMeta())

	if !p.ExpectPeek(token.LEFT_BRACE) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_BRACE"))
	}
	SwapLeadingTrailing(p.curToken, control.GetMeta())
	stmt.Control = control

	// Parse case clauses
	for !p.PeekTokenIs(token.RIGHT_BRACE) {
		t := p.peekToken
		p.NextToken()
		clause, err := p.ParseCaseStatement()
		if err != nil {
			return nil, errors.WithStack(err)
		}

		if clause.Test == nil {
			// There cannot be multiple default clauses
			if stmt.Default != -1 {
				return nil, errors.WithStack(MultipleDefaults(t))
			}
			stmt.Default = len(stmt.Cases)
		}

		// Case tests must be unique
		for _, o := range stmt.Cases {
			if clause.Test == nil || o.Test == nil || clause.Test.Operator != o.Test.Operator {
				continue
			}
			if clause.Test.Right.String() == o.Test.Right.String() {
				return nil, errors.WithStack(DuplicateCase(clause.Test.Meta))
			}
		}
		stmt.Cases = append(stmt.Cases, clause)
	}

	// There must be at least one case
	if len(stmt.Cases) == 0 {
		return nil, errors.WithStack(EmptySwitch(p.peekToken))
	}

	// Final case can't be a fallthrough case.
	lc := stmt.Cases[len(stmt.Cases)-1]
	ls := lc.Statements[len(lc.Statements)-1]
	if _, ok := ls.(*ast.FallthroughStatement); ok {
		return nil, errors.WithStack(FinalFallthrough(ls.GetMeta()))
	}

	p.NextToken() // point to RIGHT_BRACE
	SwapLeadingInfix(p.curToken, stmt.Meta)
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseBreakStatement() (*ast.BreakStatement, error) {
	stmt := &ast.BreakStatement{
		Meta: p.curToken,
	}

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	SwapLeadingInfix(p.curToken, stmt.Meta)
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseFallthroughStatement() (*ast.FallthroughStatement, error) {
	stmt := &ast.FallthroughStatement{
		Meta: p.curToken,
	}

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	SwapLeadingInfix(p.curToken, stmt.Meta)
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseCaseStatement() (*ast.CaseStatement, error) {
	stmt := &ast.CaseStatement{
		Meta:       p.curToken,
		Statements: []ast.Statement{},
	}

	switch p.curToken.Token.Type {
	case token.CASE:
		p.NextToken() // match expression

		matchExp := &ast.InfixExpression{
			Meta: p.curToken,
		}
		switch p.curToken.Token.Type {
		case token.STRING:
			exp, err := p.ParseExpression(LOWEST)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			matchExp.Operator = "=="
			matchExp.Right = exp
		case token.REGEX_MATCH:
			exp, err := p.ParsePrefixExpression()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			matchExp.Operator = "~"
			matchExp.Right = exp.Right
		default:
			return nil, UnexpectedToken(p.curToken, "string", "~")
		}
		stmt.Test = matchExp
	case token.DEFAULT:
		// nothing to do
	default:
		return nil, UnexpectedToken(p.curToken, "case", "default")
	}

	// If stmt.Test is nil, this case is "default"
	if stmt.Test != nil {
		SwapLeadingInfix(p.curToken, stmt.Meta)
	}

	if !p.ExpectPeek(token.COLON) {
		return nil, errors.WithStack(MissingColon(p.curToken))
	}

	// If stmt.Test is not nil, attach as Trailing comment to it
	if stmt.Test != nil {
		SwapLeadingTrailing(p.curToken, stmt.Test.Right.GetMeta())
	} else {
		// Otherwise, this is the "default" case, attach as infix comment to the statement
		SwapLeadingInfix(p.curToken, stmt.GetMeta())
	}

	stmt.Meta.Trailing = p.Trailing()

	for !p.PeekTokenIs(token.CASE) && !p.PeekTokenIs(token.DEFAULT) && !p.PeekTokenIs(token.RIGHT_BRACE) {
		s, err := p.ParseStatement()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		stmt.Statements = append(stmt.Statements, s)
	}

	if !p.PrevTokenIs(token.BREAK) {
		if !p.PrevTokenIs(token.FALLTHROUGH) {
			return nil, errors.WithStack(UnexpectedToken(p.prevToken, "break", "fallthrough"))
		}
		stmt.Fallthrough = true
	}

	return stmt, nil
}

func (p *Parser) ParseGotoStatement() (*ast.GotoStatement, error) {
	stmt := &ast.GotoStatement{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.IDENT) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}
	stmt.Destination = p.ParseIdent()

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}
	p.NextToken() // point to SEMICOLON
	SwapLeadingTrailing(p.curToken, stmt.Destination.Meta)
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseGotoDestination() (*ast.GotoDestinationStatement, error) {
	if !isGotoDestination(p.curToken.Token) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "IDENT"))
	}

	stmt := &ast.GotoDestinationStatement{
		Meta: p.curToken,
	}
	stmt.Name = p.ParseIdent()
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}

func (p *Parser) ParseFunctionCall() (*ast.FunctionCallStatement, error) {
	stmt := &ast.FunctionCallStatement{
		Meta:     p.curToken,
		Function: p.ParseIdent(),
	}

	p.NextToken() // point to LEFT_PAREN
	args, err := p.ParseFunctionArgumentExpressions()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Arguments = args

	if !p.PeekTokenIs(token.SEMICOLON) {
		return nil, errors.WithStack(MissingSemicolon(p.curToken))
	}

	p.NextToken() // point to SEMICOLON
	SwapLeadingInfix(p.curToken, stmt.Meta)
	stmt.Meta.Trailing = p.Trailing()

	return stmt, nil
}
