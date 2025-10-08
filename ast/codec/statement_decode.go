package codec

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

func (c *Decoder) decodeAddStatement() (*ast.AddStatement, error) {
	var err error
	stmt := &ast.AddStatement{}

	if stmt.Ident, err = c.decodeIdent(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}
	op, err := c.decodeOperator(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Operator = &ast.Operator{
		Operator: op,
	}

	if stmt.Value, err = c.decodeExpression(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}
	return stmt, nil
}

func (c *Decoder) decodeBlockStatement() (*ast.BlockStatement, error) {
	stmt := &ast.BlockStatement{}

	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto OUT
		case FIN:
			return nil, unexpectedFinByte()
		default:
			s, err := c.decode(frame)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			stmt.Statements = append(stmt.Statements, s)
		}
	}
OUT:
	return stmt, nil
}

func (c *Decoder) decodeBreakStatement() (*ast.BreakStatement, error) {
	return &ast.BreakStatement{}, nil
}

func (c *Decoder) decodeCallStatement() (*ast.CallStatement, error) {
	name, err := c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.CallStatement{
		Subroutine: name,
	}, nil
}

func (c *Decoder) decodeCaseStatement() (*ast.CaseStatement, error) {
	var err error
	stmt := &ast.CaseStatement{}

	if c.peekFrameIs(INFIX_EXPRESSION) {
		c.nextFrame()
		if stmt.Test, err = c.decodeInfixExpression(); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto OUT
		case FIN:
			return nil, unexpectedFinByte()
		default:
			s, err := c.decode(frame)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			stmt.Statements = append(stmt.Statements, s)
		}
	}
OUT:

	if c.peekFrameIs(BOOL_VALUE) {
		b, err := c.decodeBoolean(c.nextFrame())
		if err != nil {
			return nil, errors.WithStack(err)
		}
		stmt.Fallthrough = b.Value
	}

	return stmt, nil
}

func (c *Decoder) decodeDeclareStatement() (*ast.DeclareStatement, error) {
	var err error
	stmt := &ast.DeclareStatement{}

	if stmt.Name, err = c.decodeIdent(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}
	if stmt.ValueType, err = c.decodeIdent(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}

	// Check if a value is present
	if isExpressionFrame(c.peekFrame()) {
		if stmt.Value, err = c.decodeExpression(c.nextFrame()); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return stmt, nil
}

func (c *Decoder) decodeErrorStatement() (*ast.ErrorStatement, error) {
	var err error
	stmt := &ast.ErrorStatement{}

	if stmt.Code, err = c.decodeExpression(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}

	if isExpressionFrame(c.peekFrame()) {
		if stmt.Argument, err = c.decodeExpression(c.nextFrame()); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return stmt, nil
}

func (c *Decoder) decodeEsiStatement() (*ast.EsiStatement, error) {
	return &ast.EsiStatement{}, nil
}

func (c *Decoder) decodeFallthroughStatement() (*ast.FallthroughStatement, error) {
	return &ast.FallthroughStatement{}, nil
}

func (c *Decoder) decodeFunctionCallStatement() (*ast.FunctionCallStatement, error) {
	var err error
	stmt := &ast.FunctionCallStatement{}

	if stmt.Function, err = c.decodeIdent(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}

	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto OUT
		case FIN:
			return nil, unexpectedFinByte()
		default:
			expr, err := c.decodeExpression(frame)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			stmt.Arguments = append(stmt.Arguments, expr)
		}
	}
OUT:

	return stmt, nil
}

func (c *Decoder) decodeGotoStatement() (*ast.GotoStatement, error) {
	var err error
	stmt := &ast.GotoStatement{}

	if stmt.Destination, err = c.decodeIdent(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}

	return stmt, nil
}

func (c *Decoder) decodeGotoDestionationStatement() (*ast.GotoDestinationStatement, error) {
	var err error
	stmt := &ast.GotoDestinationStatement{}

	if stmt.Name, err = c.decodeIdent(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}

	return stmt, nil
}

func (c *Decoder) decodeIfStatement() (*ast.IfStatement, error) {
	var err error
	stmt := &ast.IfStatement{
		Another: []*ast.IfStatement{},
	}

	keyword, err := c.decodeString(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Keyword = keyword.Value

	if stmt.Condition, err = c.decodeExpression(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}

	// Consequence is block statemen
	if !c.peekFrameIs(BLOCK_STATEMENT) {
		return nil, typeMismatch(BLOCK_STATEMENT, c.peekFrame().Type())
	}
	c.nextFrame() // point to BLOCK_STATEMENT frame

	if stmt.Consequence, err = c.decodeBlockStatement(); err != nil {
		return nil, errors.WithStack(err)
	}

	// Another
	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto ANOTHER_END
		case FIN:
			return nil, unexpectedFinByte()
		case IF_STATEMENT:
			another, err := c.decodeIfStatement()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			stmt.Another = append(stmt.Another, another)
		}
	}
ANOTHER_END:

	if c.peekFrameIs(ELSE_STATEMENT) {
		c.nextFrame() // point to ELSE_STATEMENT frame

		if !c.peekFrameIs(BLOCK_STATEMENT) {
			return nil, typeMismatch(BLOCK_STATEMENT, c.peekFrame().Type())
		}
		c.nextFrame() // point to BLOCK_STATEMENT frame

		alternative := &ast.ElseStatement{}
		if alternative.Consequence, err = c.decodeBlockStatement(); err != nil {
			return nil, errors.WithStack(err)
		}

		stmt.Alternative = alternative
	}

	return stmt, nil
}

func (c *Decoder) decodeImportStatement() (*ast.ImportStatement, error) {
	name, err := c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.ImportStatement{
		Name: name,
	}, nil
}

func (c *Decoder) decodeIncludeStatement() (*ast.IncludeStatement, error) {
	mod, err := c.decodeString(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.IncludeStatement{
		Module: mod,
	}, nil
}

func (c *Decoder) decodeLogStatement() (*ast.LogStatement, error) {
	expr, err := c.decodeExpression(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.LogStatement{
		Value: expr,
	}, nil
}

func (c *Decoder) decodeRemoveStatement() (*ast.RemoveStatement, error) {
	ident, err := c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.RemoveStatement{
		Ident: ident,
	}, nil
}

func (c *Decoder) decodeRestartStatement() (*ast.RestartStatement, error) {
	return &ast.RestartStatement{}, nil
}

func (c *Decoder) decodeReturnStatement() (*ast.ReturnStatement, error) {
	stmt := &ast.ReturnStatement{}

	hp, err := c.decodeBoolean(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.HasParenthesis = hp.Value
	if isExpressionFrame(c.peekFrame()) {
		if stmt.ReturnExpression, err = c.decodeExpression(c.nextFrame()); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return stmt, nil
}

func (c *Decoder) decodeSetStatement() (*ast.SetStatement, error) {
	var err error
	stmt := &ast.SetStatement{}

	if stmt.Ident, err = c.decodeIdent(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}

	op, err := c.decodeOperator(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Operator = &ast.Operator{
		Operator: op,
	}

	if stmt.Value, err = c.decodeExpression(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}
	return stmt, nil
}

func (c *Decoder) decodeSwitchStatement() (*ast.SwitchStatement, error) {
	var err error
	stmt := &ast.SwitchStatement{}

	control, err := c.decodeExpression(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	stmt.Control = &ast.SwitchControl{
		Expression: control,
	}

	// cases
	for {
		frame := c.nextFrame()
		switch frame.Type() {
		case END:
			goto CASE_END
		case FIN:
			return nil, unexpectedFinByte()
		case CASE_STATEMENT:
			c, err := c.decodeCaseStatement()
			if err != nil {
				return nil, errors.WithStack(err)
			}
			stmt.Cases = append(stmt.Cases, c)
		default:
			return nil, typeMismatch(CASE_STATEMENT, frame.Type())
		}
	}
CASE_END:

	// Default
	if c.peekFrameIs(INTEGER_VALUE) {
		d, err := c.decodeInteger(c.nextFrame())
		if err != nil {
			return nil, errors.WithStack(err)
		}
		stmt.Default = int(d.Value)
	}

	return stmt, nil
}

func (c *Decoder) decodeSyntheticStatement() (*ast.SyntheticStatement, error) {
	expr, err := c.decodeExpression(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.SyntheticStatement{
		Value: expr,
	}, nil
}

func (c *Decoder) decodeSyntheticBase64Statement() (*ast.SyntheticBase64Statement, error) {
	expr, err := c.decodeExpression(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.SyntheticBase64Statement{
		Value: expr,
	}, nil
}

func (c *Decoder) decodeUnsetStatement() (*ast.UnsetStatement, error) {
	ident, err := c.decodeIdent(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.UnsetStatement{
		Ident: ident,
	}, nil
}
