package codec

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/ysugimoto/falco/ast"
)

func (c *Encoder) encodeExpression(expr ast.Expression) *Frame {
	switch t := expr.(type) {
	// Combination Expressions
	case *ast.GroupedExpression:
		return c.encodeGroupedExpression(t)
	case *ast.InfixExpression:
		return c.encodeInfixExpression(t)
	case *ast.PostfixExpression:
		return c.encodePostfixExpression(t)
	case *ast.PrefixExpression:
		return c.encodePrefixExpression(t)
	case *ast.IfExpression:
		return c.encodeIfExpression(t)
	case *ast.FunctionCallExpression:
		return c.encodeFunctionCallExpression(t)

	// Values
	case *ast.Ident:
		return c.encodeIdent(t)
	case *ast.String:
		return c.encodeString(t)
	case *ast.IP:
		return c.encodeIP(t)
	case *ast.Integer:
		return c.encodeInteger(t)
	case *ast.Float:
		return c.encodeFloat(t)
	case *ast.Boolean:
		return c.encodeBoolean(t)
	case *ast.RTime:
		return c.encodeRTime(t)

	// Unknown
	default:
		return &Frame{
			frameType: UNKNOWN,
			buffer:    []byte{},
		}
	}

}

func (c *Encoder) encodeGroupedExpression(expr *ast.GroupedExpression) *Frame {
	return &Frame{
		frameType: GROUPED_EXPRESSION,
		buffer:    c.encodeExpression(expr.Right).Encode(),
	}
}

func (c *Encoder) encodeInfixExpression(expr *ast.InfixExpression) *Frame {
	buf := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(buf)

	buf.Reset()
	// Left expression might be nil (switch.case test)
	if expr.Left != nil {
		buf.Write(c.encodeExpression(expr.Left).Encode())
	}
	buf.Write(c.encodeOperator(expr.Operator).Encode())
	buf.Write(c.encodeExpression(expr.Right).Encode())

	return &Frame{
		frameType: INFIX_EXPRESSION,
		buffer:    buf.Bytes(),
	}
}

func (c *Encoder) encodePostfixExpression(expr *ast.PostfixExpression) *Frame {
	buf := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(buf)

	buf.Reset()
	buf.Write(c.encodeExpression(expr.Left).Encode())
	buf.Write(c.encodeOperator(expr.Operator).Encode())

	return &Frame{
		frameType: POSTFIX_EXPRESSION,
		buffer:    buf.Bytes(),
	}
}

func (c *Encoder) encodePrefixExpression(expr *ast.PrefixExpression) *Frame {
	buf := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(buf)

	buf.Reset()
	buf.Write(c.encodeOperator(expr.Operator).Encode())
	buf.Write(c.encodeExpression(expr.Right).Encode())

	return &Frame{
		frameType: PREFIX_EXPRESSION,
		buffer:    buf.Bytes(),
	}
}

func (c *Encoder) encodeIfExpression(expr *ast.IfExpression) *Frame {
	buf := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(buf)
	buf.Reset()

	buf.Write(c.encodeExpression(expr.Condition).Encode())
	buf.Write(c.encodeExpression(expr.Consequence).Encode())
	buf.Write(c.encodeExpression(expr.Alternative).Encode())

	return &Frame{
		frameType: IF_EXPRESSION,
		buffer:    buf.Bytes(),
	}
}

func (c *Encoder) encodeFunctionCallExpression(expr *ast.FunctionCallExpression) *Frame {
	buf := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(buf)
	buf.Reset()

	buf.Write(c.encodeIdent(expr.Function).Encode())
	for _, arg := range expr.Arguments {
		buf.Write(c.encodeExpression(arg).Encode())
	}
	buf.Write(end())

	return &Frame{
		frameType: FUNCTIONCALL_EXPRESSION,
		buffer:    buf.Bytes(),
	}
}

func (c *Encoder) encodeIdent(expr *ast.Ident) *Frame {
	return &Frame{
		frameType: IDENT_VALUE,
		buffer:    stringToBytes(expr.Value),
	}
}

func (c *Encoder) encodeString(expr *ast.String) *Frame {
	return &Frame{
		frameType: STRING_VALUE,
		buffer:    stringToBytes(expr.Value),
	}
}

func (c *Encoder) encodeIP(expr *ast.IP) *Frame {
	return &Frame{
		frameType: IP_VALUE,
		buffer:    stringToBytes(expr.Value),
	}
}

func (c *Encoder) encodeRTime(expr *ast.RTime) *Frame {
	return &Frame{
		frameType: RTIME_VALUE,
		buffer:    stringToBytes(expr.Value),
	}
}

func (c *Encoder) encodeInteger(expr *ast.Integer) *Frame {
	bin := make([]byte, 8)
	binary.BigEndian.PutUint64(bin, uint64(expr.Value))

	return &Frame{
		frameType: INTEGER_VALUE,
		buffer:    bin,
	}
}

func (c *Encoder) encodeFloat(expr *ast.Float) *Frame {
	bin := make([]byte, 8)
	binary.BigEndian.PutUint64(bin, math.Float64bits(expr.Value))

	return &Frame{
		frameType: FLOAT_VALUE,
		buffer:    bin,
	}
}

func (c *Encoder) encodeBoolean(expr *ast.Boolean) *Frame {
	v := byte(0x00)
	if expr.Value {
		v = byte(0x01)
	}

	return &Frame{
		frameType: BOOL_VALUE,
		buffer:    []byte{v},
	}
}

func (c *Encoder) encodeOperator(op string) *Frame {
	return &Frame{
		frameType: OPERATOR,
		buffer:    stringToBytes(op),
	}
}
