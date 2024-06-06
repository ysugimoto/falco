package codec

import "github.com/ysugimoto/falco/ast"

func (c *Codec) encodeExpression(expr ast.Expression) []byte {
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

	// Values
	case *ast.Ident:
		return packIdent(t.Value)
	case *ast.String:
		return packString(t.Value)
	case *ast.IP:
		return packIP(t.Value)
	case *ast.Integer:
		return packInteger(t.Value)
	case *ast.Float:
		return packFloat(t.Value)
	case *ast.Boolean:
		return packBoolean(t.Value)
	case *ast.RTime:
		return packRTime(t.Value)
	}

	return []byte{byte(UNKNOWN)}
}

func (c *Codec) encodeGroupedExpression(expr *ast.GroupedExpression) []byte {
	return pack(GROUPED_EXPRESSION, c.encodeExpression(expr.Right))
}

func (c *Codec) encodeInfixExpression(expr *ast.InfixExpression) []byte {
	var ret []byte

	ret = append(ret, c.encodeExpression(expr.Left)...)
	ret = append(ret, packString(expr.Operator)...)
	ret = append(ret, c.encodeExpression(expr.Right)...)

	return pack(INFIX_EXPRESSION, ret)
}

func (c *Codec) encodePostfixExpression(expr *ast.PostfixExpression) []byte {
	var ret []byte

	ret = append(ret, c.encodeExpression(expr.Left)...)
	ret = append(ret, packString(expr.Operator)...)

	return pack(POSTFIX_EXPRESSION, ret)
}

func (c *Codec) encodePrefixExpression(expr *ast.PrefixExpression) []byte {
	var ret []byte

	ret = append(ret, packString(expr.Operator)...)
	ret = append(ret, c.encodeExpression(expr.Right)...)

	return pack(PREFIX_EXPRESSION, ret)
}
