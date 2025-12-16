package codec

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

func (c *Decoder) decodeExpression(frame *Frame) (ast.Expression, error) {
	var err error
	var expr ast.Expression

	switch frame.Type() {
	case GROUPED_EXPRESSION:
		expr, err = c.decodeGroupedExpression()
	case INFIX_EXPRESSION:
		expr, err = c.decodeInfixExpression()
	case POSTFIX_EXPRESSION:
		expr, err = c.decodePostfixExpression()
	case PREFIX_EXPRESSION:
		expr, err = c.decodePrefixExpression()
	case IF_EXPRESSION:
		expr, err = c.decodeIfExpression()
	case FUNCTIONCALL_EXPRESSION:
		expr, err = c.decodeFunctionCallExpression()

	case FLOAT_VALUE:
		expr, err = c.decodeFloat(frame)
	case IP_VALUE:
		expr, err = c.decodeIP(frame)
	case IDENT_VALUE:
		expr, err = c.decodeIdent(frame)
	case BOOL_VALUE:
		expr, err = c.decodeBoolean(frame)
	case INTEGER_VALUE:
		expr, err = c.decodeInteger(frame)
	case RTIME_VALUE:
		expr, err = c.decodeRTime(frame)
	case STRING_VALUE:
		expr, err = c.decodeString(frame)
	default:
		err = decodeError(fmt.Errorf(
			"unexpected FrameType found: %s", frame.String(),
		))
	}

	if err != nil {
		return nil, err
	}
	return expr, nil
}

func (c *Decoder) decodeGroupedExpression() (*ast.GroupedExpression, error) {
	right, err := c.decodeExpression(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.GroupedExpression{
		Right: right,
	}, nil
}

func (c *Decoder) decodeInfixExpression() (*ast.InfixExpression, error) {
	var err error
	var left ast.Expression

	if isExpressionFrame(c.peekFrame()) {
		left, err = c.decodeExpression(c.nextFrame())
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	operator, err := c.decodeOperator(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	right, err := c.decodeExpression(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.InfixExpression{
		Left:     left,
		Operator: operator,
		Right:    right,
	}, nil
}

func (c *Decoder) decodePostfixExpression() (*ast.PostfixExpression, error) {
	left, err := c.decodeExpression(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	operator, err := c.decodeOperator(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.PostfixExpression{
		Left:     left,
		Operator: operator,
	}, nil
}

func (c *Decoder) decodePrefixExpression() (*ast.PrefixExpression, error) {
	operator, err := c.decodeOperator(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	right, err := c.decodeExpression(c.nextFrame())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.PrefixExpression{
		Operator: operator,
		Right:    right,
	}, nil
}

func (c *Decoder) decodeIfExpression() (*ast.IfExpression, error) {
	var err error
	expr := &ast.IfExpression{}

	if expr.Condition, err = c.decodeExpression(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}
	if expr.Consequence, err = c.decodeExpression(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}
	if expr.Alternative, err = c.decodeExpression(c.nextFrame()); err != nil {
		return nil, errors.WithStack(err)
	}

	return expr, nil
}

func (c *Decoder) decodeFunctionCallExpression() (*ast.FunctionCallExpression, error) {
	var err error
	fn := &ast.FunctionCallExpression{}

	if fn.Function, err = c.decodeIdent(c.nextFrame()); err != nil {
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
			fn.Arguments = append(fn.Arguments, expr)
		}
	}
OUT:

	return fn, nil
}

func (c *Decoder) decodeIdent(frame *Frame) (*ast.Ident, error) {
	if frame.Type() != IDENT_VALUE {
		return nil, typeMismatch(IDENT_VALUE, frame.Type())
	}
	buf, err := frame.Read(c.r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.Ident{
		Value: bytesToString(buf),
	}, nil
}

func (c *Decoder) decodeString(frame *Frame) (*ast.String, error) {
	if frame.Type() != STRING_VALUE {
		return nil, typeMismatch(STRING_VALUE, frame.Type())
	}
	buf, err := frame.Read(c.r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.String{
		Value: bytesToString(buf),
	}, nil
}

func (c *Decoder) decodeRTime(frame *Frame) (*ast.RTime, error) {
	if frame.Type() != RTIME_VALUE {
		return nil, typeMismatch(RTIME_VALUE, frame.Type())
	}
	buf, err := frame.Read(c.r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.RTime{
		Value: bytesToString(buf),
	}, nil
}

func (c *Decoder) decodeIP(frame *Frame) (*ast.IP, error) {
	if frame.Type() != IP_VALUE {
		return nil, typeMismatch(IP_VALUE, frame.Type())
	}
	buf, err := frame.Read(c.r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.IP{
		Value: bytesToString(buf),
	}, nil
}

func (c *Decoder) decodeInteger(frame *Frame) (*ast.Integer, error) {
	if frame.Type() != INTEGER_VALUE {
		return nil, typeMismatch(INTEGER_VALUE, frame.Type())
	}
	buf, err := frame.Read(c.r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	v := binary.BigEndian.Uint64(buf)
	return &ast.Integer{
		Value: int64(v),
	}, nil
}

func (c *Decoder) decodeFloat(frame *Frame) (*ast.Float, error) {
	if frame.Type() != FLOAT_VALUE {
		return nil, typeMismatch(FLOAT_VALUE, frame.Type())
	}
	buf, err := frame.Read(c.r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	bits := binary.BigEndian.Uint64(buf)
	return &ast.Float{
		Value: math.Float64frombits(bits),
	}, nil
}

func (c *Decoder) decodeBoolean(frame *Frame) (*ast.Boolean, error) {
	if frame.Type() != BOOL_VALUE {
		return nil, typeMismatch(BOOL_VALUE, frame.Type())
	}
	buf, err := frame.Read(c.r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &ast.Boolean{
		Value: buf[0] == 0x01,
	}, nil
}

func (c *Decoder) decodeOperator(frame *Frame) (string, error) {
	if frame.Type() != OPERATOR {
		return "", typeMismatch(OPERATOR, frame.Type())
	}
	buf, err := frame.Read(c.r)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return bytesToString(buf), nil
}
