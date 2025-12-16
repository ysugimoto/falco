package parser

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

func (p *Parser) registerExpressionParsers() {
	p.prefixParsers = map[token.TokenType]prefixParser{
		token.IDENT:            func() (ast.Expression, error) { return p.ParseIdent(), nil },
		token.STRING:           func() (ast.Expression, error) { return p.ParseString() },
		token.OPEN_LONG_STRING: func() (ast.Expression, error) { return p.ParseLongString() },
		token.INT:              func() (ast.Expression, error) { return p.ParseInteger() },
		token.FLOAT:            func() (ast.Expression, error) { return p.ParseFloat() },
		token.RTIME:            func() (ast.Expression, error) { return p.ParseRTime() },
		token.NOT:              func() (ast.Expression, error) { return p.ParsePrefixExpression() },
		token.MINUS:            func() (ast.Expression, error) { return p.ParsePrefixExpression() },
		token.PLUS:             func() (ast.Expression, error) { return p.ParsePrefixExpression() },
		token.TRUE:             func() (ast.Expression, error) { return p.ParseBoolean(), nil },
		token.FALSE:            func() (ast.Expression, error) { return p.ParseBoolean(), nil },
		token.LEFT_PAREN:       func() (ast.Expression, error) { return p.ParseGroupedExpression() },
		token.IF:               func() (ast.Expression, error) { return p.ParseIfExpression() },
		token.ERROR:            func() (ast.Expression, error) { return p.ParseIdent(), nil },
		token.RESTART:          func() (ast.Expression, error) { return p.ParseIdent(), nil },
	}
	p.infixParsers = map[token.TokenType]infixParser{
		// If VCL has Plus sign, explicitly concatenation.
		token.PLUS: func(left ast.Expression) (ast.Expression, error) {
			return p.ParseInfixStringConcatExpression(left, true)
		},
		token.IF: func(left ast.Expression) (ast.Expression, error) {
			return p.ParseInfixStringConcatExpression(left, false)
		},
		token.STRING: func(left ast.Expression) (ast.Expression, error) {
			return p.ParseInfixStringConcatExpression(left, false)
		},
		token.OPEN_LONG_STRING: func(left ast.Expression) (ast.Expression, error) {
			return p.ParseInfixStringConcatExpression(left, false)
		},
		token.IDENT: func(left ast.Expression) (ast.Expression, error) {
			return p.ParseInfixStringConcatExpression(left, false)
		},
		token.MINUS:              p.ParseInfixExpression,
		token.EQUAL:              p.ParseInfixExpression,
		token.NOT_EQUAL:          p.ParseInfixExpression,
		token.GREATER_THAN:       p.ParseInfixExpression,
		token.GREATER_THAN_EQUAL: p.ParseInfixExpression,
		token.LESS_THAN:          p.ParseInfixExpression,
		token.LESS_THAN_EQUAL:    p.ParseInfixExpression,
		token.REGEX_MATCH:        p.ParseInfixExpression,
		token.NOT_REGEX_MATCH:    p.ParseInfixExpression,
		token.LEFT_PAREN:         p.ParseFunctionCallExpression,
		token.AND:                p.ParseInfixExpression,
		token.OR:                 p.ParseInfixExpression,
	}
	p.postfixParsers = map[token.TokenType]postfixParser{
		token.PERCENT: p.ParsePostfixExpression,
	}
}

func (p *Parser) ParseExpression(precedence int) (ast.Expression, error) {
	// Note: trim comment inside expression list
	// For example:
	// if (req.http.Foo && /* comment */ req.http.Bar) { ... } // -> trim  /* comment */ token
	// if (
	//   req.http.Foo &&
	//   # Some line comment here // trim this line
	//   req.http,Bar
	// ) { ... }
	prefix, ok := p.prefixParsers[p.curToken.Token.Type]
	if !ok {
		return nil, errors.WithStack(UndefinedPrefix(p.curToken))
	}

	left, err := prefix()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// same as prefix expression
	for !p.PeekTokenIs(token.SEMICOLON) && precedence < p.peekPrecedence() {
		infix, ok := p.infixParsers[p.peekToken.Token.Type]
		if !ok {
			if postfix, ok := p.postfixParsers[p.peekToken.Token.Type]; ok {
				p.NextToken()
				left, err = postfix(left)
				if err != nil {
					return nil, errors.WithStack(err)
				}
				continue
			}
			return left, nil
		}

		SwapLeadingTrailing(p.peekToken, left.GetMeta())
		p.NextToken()
		left, err = infix(left)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		continue
	}

	if p.PeekTokenIs(token.SEMICOLON) {
		SwapLeadingTrailing(p.peekToken, left.GetMeta())
	}

	return left, nil
}

func (p *Parser) ParsePrefixExpression() (*ast.PrefixExpression, error) {
	exp := &ast.PrefixExpression{
		Meta:     p.curToken,
		Operator: p.curToken.Token.Literal,
	}

	p.NextToken() // point to expression start
	right, err := p.ParseExpression(PREFIX)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Right = right
	exp.EndLine = right.GetMeta().EndLine
	exp.EndPosition = right.GetMeta().EndPosition

	return exp, nil
}

func (p *Parser) ParseGroupedExpression() (*ast.GroupedExpression, error) {
	exp := &ast.GroupedExpression{
		Meta: p.curToken,
	}

	p.NextToken() // point to expression start
	right, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Right = right

	if !p.ExpectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	exp.EndLine = right.GetMeta().EndLine
	exp.EndPosition = right.GetMeta().EndPosition + 1

	return exp, nil
}

func (p *Parser) ParseIfExpression() (*ast.IfExpression, error) {
	exp := &ast.IfExpression{
		Meta: p.curToken,
	}

	if !p.ExpectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}

	p.NextToken() // point to condition expression start
	cond, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Condition = cond

	if !p.ExpectPeek(token.COMMA) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
	}

	p.NextToken() // point to consequence expression
	exp.Consequence, err = p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.ExpectPeek(token.COMMA) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
	}

	p.NextToken() // point to alternative expression
	exp.Alternative, err = p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.ExpectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	exp.EndLine = p.curToken.Token.Line
	exp.EndPosition = p.curToken.Token.Position

	return exp, nil
}

func (p *Parser) ParseInfixExpression(left ast.Expression) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Meta:     left.GetMeta().CloneWithoutComments(),
		Operator: p.curToken.Token.Literal,
		Left:     left,
	}

	precedence := p.curPrecedence()
	p.NextToken() // point to right expression start
	right, err := p.ParseExpression(precedence)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Right = right
	exp.EndLine = right.GetMeta().EndLine
	exp.EndPosition = right.GetMeta().EndPosition

	return exp, nil
}

func (p *Parser) ParseInfixStringConcatExpression(left ast.Expression, explicit bool) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Meta: left.GetMeta().CloneWithoutComments(),
		// VCL can concat string without "+" operator, consecutive token.
		// But we explicitly define as "+" operator to make clearly
		Operator: "+",
		Explicit: explicit,
		Left:     left,
	}

	precedence := p.curPrecedence()
	right, err := p.ParseExpression(precedence)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Right = right
	exp.EndLine = right.GetMeta().EndLine
	exp.EndPosition = right.GetMeta().EndPosition

	return exp, nil
}

func (p *Parser) ParsePostfixExpression(left ast.Expression) (ast.Expression, error) {
	exp := &ast.PostfixExpression{
		Meta: p.curToken,
		Left: left,
	}
	exp.Operator = p.curToken.Token.Literal

	// Swap start/end line and position
	exp.EndLine = p.curToken.Token.Line
	exp.EndPosition = p.curToken.Token.Position
	exp.Token.Line = left.GetMeta().Token.Line
	exp.Token.Position = left.GetMeta().Token.Position

	return exp, nil
}

func (p *Parser) ParseFunctionCallExpression(fn ast.Expression) (ast.Expression, error) {
	ident, ok := fn.(*ast.Ident)
	if !ok {
		return nil, errors.New("Function name must be IDENT")
	}
	exp := &ast.FunctionCallExpression{
		Meta:     ident.GetMeta().Clone(),
		Function: ident,
	}

	args, err := p.ParseFunctionArgumentExpressions()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Arguments = args
	exp.EndLine = p.curToken.Token.Line
	exp.EndPosition = p.curToken.Token.Position

	return exp, nil
}

func (p *Parser) ParseFunctionArgumentExpressions() ([]ast.Expression, error) {
	list := []ast.Expression{}

	if p.PeekTokenIs(token.RIGHT_PAREN) {
		p.NextToken() // point to RIGHT_PAREN, means nothing argument is specified
		return list, nil
	}

	p.NextToken() // point to first argument expression
	item, err := p.ParseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	list = append(list, item)

	for p.PeekTokenIs(token.COMMA) {
		p.NextToken() // point to COMMA
		SwapLeadingTrailing(p.curToken, list[len(list)-1].GetMeta())
		p.NextToken() // point to next argument expression
		item, err := p.ParseExpression(LOWEST)
		if err != nil {
			return nil, err
		}
		list = append(list, item)
	}

	if !p.ExpectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}
	SwapLeadingTrailing(p.curToken, list[len(list)-1].GetMeta())

	return list, nil
}
