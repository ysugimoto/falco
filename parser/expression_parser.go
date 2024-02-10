package parser

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
)

func (p *Parser) registerExpressionParsers() {
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
		token.ERROR:      func() (ast.Expression, error) { return p.parseIdent(), nil },
		token.RESTART:    func() (ast.Expression, error) { return p.parseIdent(), nil },
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
	p.postfixParsers = map[token.TokenType]postfixParser{
		token.PERCENT: p.parsePostfixExpression,
	}
}

// Expose global function to be called externally
func (p *Parser) ParseExpression(precedence int) (ast.Expression, error) {
	return p.parseExpression(precedence)
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
	prefix, ok := p.prefixParsers[p.curToken.Token.Type]
	if !ok {
		return nil, errors.WithStack(UndefinedPrefix(p.curToken))
	}

	left, err := prefix()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// same as prefix expression
	for !p.peekTokenIs(token.SEMICOLON) && precedence < p.peekPrecedence() {
		infix, ok := p.infixParsers[p.peekToken.Token.Type]
		if !ok {
			if postfix, ok := p.postfixParsers[p.peekToken.Token.Type]; ok {
				p.nextToken()
				left, err = postfix(left)
				if err != nil {
					return nil, errors.WithStack(err)
				}
				continue
			}
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

func (p *Parser) parsePrefixExpression() (*ast.PrefixExpression, error) {
	exp := &ast.PrefixExpression{
		Meta:     p.curToken,
		Operator: p.curToken.Token.Literal,
	}

	p.nextToken() // point to expression start
	right, err := p.parseExpression(PREFIX)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Right = right

	return exp, nil
}

func (p *Parser) parseGroupedExpression() (*ast.GroupedExpression, error) {
	exp := &ast.GroupedExpression{
		Meta: p.curToken,
	}

	p.nextToken() // point to expression start
	right, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Right = right

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	return exp, nil
}

func (p *Parser) parseIfExpression() (*ast.IfExpression, error) {
	exp := &ast.IfExpression{
		Meta: p.curToken,
	}

	if !p.expectPeek(token.LEFT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "LEFT_PAREN"))
	}

	p.nextToken() // point to condition expression start
	cond, err := p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Condition = cond

	if !p.expectPeek(token.COMMA) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
	}

	p.nextToken() // point to consequence expression
	exp.Consequence, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.COMMA) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "COMMA"))
	}

	p.nextToken() // point to alternative expression
	exp.Alternative, err = p.parseExpression(LOWEST)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	return exp, nil
}

func (p *Parser) parseInfixExpression(left ast.Expression) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Meta:     p.curToken, // point to operator token
		Operator: p.curToken.Token.Literal,
		Left:     left,
	}

	precedence := p.curPrecedence()
	p.nextToken() // point to right expression start
	right, err := p.parseExpression(precedence)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Right = right

	return exp, nil
}

func (p *Parser) parseInfixStringConcatExpression(left ast.Expression) (ast.Expression, error) {
	exp := &ast.InfixExpression{
		Meta: p.curToken,
		// VCL can concat string without "+" operator, consecutive token.
		// But we explicitly define as "+" operator to make clearly
		Operator: "+",
		Left:     left,
	}

	precedence := p.curPrecedence()
	right, err := p.parseExpression(precedence)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Right = right

	return exp, nil
}

func (p *Parser) parsePostfixExpression(left ast.Expression) (ast.Expression, error) {
	exp := &ast.PostfixExpression{
		Meta: p.curToken,
		Left: left,
	}
	exp.Operator = p.curToken.Token.Literal

	return exp, nil
}

func (p *Parser) parseFunctionCallExpression(fn ast.Expression) (ast.Expression, error) {
	ident, ok := fn.(*ast.Ident)
	if !ok {
		return nil, errors.New("Function name must be IDENT")
	}
	exp := &ast.FunctionCallExpression{
		Meta:     p.curToken,
		Function: ident,
	}

	args, err := p.parseFunctionArgumentExpressions()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	exp.Arguments = args

	return exp, nil
}

func (p *Parser) parseFunctionArgumentExpressions() ([]ast.Expression, error) {
	list := []ast.Expression{}

	if p.peekTokenIs(token.RIGHT_PAREN) {
		p.nextToken() // point to RIGHT_PAREN, means nothing argument is specified
		return list, nil
	}

	p.nextToken() // point to first argument expression
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

	if !p.expectPeek(token.RIGHT_PAREN) {
		return nil, errors.WithStack(UnexpectedToken(p.peekToken, "RIGHT_PAREN"))
	}

	return list, nil
}
