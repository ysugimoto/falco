package codec

import (
	"bytes"

	"github.com/ysugimoto/falco/ast"
)

func (c *Encoder) encodeAddStatement(stmt *ast.AddStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(stmt.Ident).Encode())
	w.Write(c.encodeOperator(stmt.Operator.Operator).Encode())
	w.Write(c.encodeExpression(stmt.Value).Encode())

	return &Frame{
		frameType: ADD_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeBlockStatement(stmt *ast.BlockStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	for _, s := range stmt.Statements {
		frame, _ := c.encode(s) // nolint:errcheck
		w.Write(frame.Encode())
	}
	w.Write(end())

	return &Frame{
		frameType: BLOCK_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeBreakStatement() *Frame {
	return &Frame{
		frameType: BREAK_STATEMENT,
		buffer:    []byte{},
	}
}

func (c *Encoder) encodeCallStatement(stmt *ast.CallStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(stmt.Subroutine).Encode())

	return &Frame{
		frameType: CALL_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeCaseStatement(stmt *ast.CaseStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	if stmt.Test != nil {
		w.Write(c.encodeInfixExpression(stmt.Test).Encode())
	}

	for _, s := range stmt.Statements {
		frame, _ := c.encode(s) // nolint:errcheck
		w.Write(frame.Encode())
	}
	w.Write(end())

	if stmt.Fallthrough {
		w.Write(c.encodeBoolean(&ast.Boolean{Value: stmt.Fallthrough}).Encode())
	}

	return &Frame{
		frameType: CASE_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeDeclareStatement(stmt *ast.DeclareStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(stmt.Name).Encode())
	w.Write(c.encodeIdent(stmt.ValueType).Encode())

	return &Frame{
		frameType: DECLARE_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeErrorStatement(stmt *ast.ErrorStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeExpression(stmt.Code).Encode())
	if stmt.Argument != nil {
		w.Write(c.encodeExpression(stmt.Argument).Encode())
	}

	return &Frame{
		frameType: ERROR_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeEsiStatement() *Frame {
	return &Frame{
		frameType: ESI_STATEMENT,
		buffer:    []byte{},
	}
}

func (c *Encoder) encodeFallthroughStatement() *Frame {
	return &Frame{
		frameType: FALLTHROUGH_STATEMENT,
		buffer:    []byte{},
	}
}

func (c *Encoder) encodeFunctionCallStatement(stmt *ast.FunctionCallStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(stmt.Function).Encode())
	for _, arg := range stmt.Arguments {
		w.Write(c.encodeExpression(arg).Encode())
	}
	w.Write(end())

	return &Frame{
		frameType: FUNCTIONCALL_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeGotoStatement(stmt *ast.GotoStatement) *Frame {
	return &Frame{
		frameType: GOTO_STATEMENT,
		buffer:    c.encodeIdent(stmt.Destination).Encode(),
	}
}

func (c *Encoder) encodeGotoDestinationStatement(stmt *ast.GotoDestinationStatement) *Frame {
	return &Frame{
		frameType: GOTO_DESTINATION_STATEMENT,
		buffer:    c.encodeIdent(stmt.Name).Encode(),
	}
}

func (c *Encoder) encodeIfStatement(stmt *ast.IfStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeString(&ast.String{Value: stmt.Keyword}).Encode())
	w.Write(c.encodeExpression(stmt.Condition).Encode())
	w.Write(c.encodeBlockStatement(stmt.Consequence).Encode())

	// Else if
	for _, a := range stmt.Another {
		w.Write(c.encodeIfStatement(a).Encode())
	}
	w.Write(end())

	// Else
	if stmt.Alternative != nil {
		w.Write(c.encodeElseStatement(stmt.Alternative).Encode())
	}

	return &Frame{
		frameType: IF_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeElseStatement(stmt *ast.ElseStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeBlockStatement(stmt.Consequence).Encode())

	return &Frame{
		frameType: ELSE_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeImportStatement(stmt *ast.ImportStatement) *Frame {
	return &Frame{
		frameType: IMPORT_STATEMENT,
		buffer:    c.encodeIdent(stmt.Name).Encode(),
	}
}

func (c *Encoder) encodeIncludeStatement(stmt *ast.IncludeStatement) *Frame {
	return &Frame{
		frameType: INCLUDE_STATEMENT,
		buffer:    c.encodeString(stmt.Module).Encode(),
	}
}

func (c *Encoder) encodeLogStatement(stmt *ast.LogStatement) *Frame {
	return &Frame{
		frameType: LOG_STATEMENT,
		buffer:    c.encodeExpression(stmt.Value).Encode(),
	}
}

func (c *Encoder) encodeRemoveStatement(stmt *ast.RemoveStatement) *Frame {
	return &Frame{
		frameType: REMOVE_STATEMENT,
		buffer:    c.encodeIdent(stmt.Ident).Encode(),
	}
}

func (c *Encoder) encodeRestartStatement() *Frame {
	return &Frame{
		frameType: RESTART_STATEMENT,
		buffer:    []byte{},
	}
}

func (c *Encoder) encodeReturnStatement(stmt *ast.ReturnStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeBoolean(&ast.Boolean{Value: stmt.HasParenthesis}).Encode())
	if stmt.ReturnExpression != nil {
		w.Write(c.encodeExpression(stmt.ReturnExpression).Encode())
	}

	return &Frame{
		frameType: RETURN_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeSetStatement(stmt *ast.SetStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeIdent(stmt.Ident).Encode())
	w.Write(c.encodeOperator(stmt.Operator.Operator).Encode())
	w.Write(c.encodeExpression(stmt.Value).Encode())

	return &Frame{
		frameType: SET_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeSwitchStatement(stmt *ast.SwitchStatement) *Frame {
	w := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeExpression(stmt.Control.Expression).Encode())
	for _, sc := range stmt.Cases {
		w.Write(c.encodeCaseStatement(sc).Encode())
	}
	w.Write(end())
	w.Write(c.encodeInteger(&ast.Integer{Value: int64(stmt.Default)}).Encode())

	return &Frame{
		frameType: SWITCH_STATEMENT,
		buffer:    w.Bytes(),
	}
}

func (c *Encoder) encodeSyntheticStatement(stmt *ast.SyntheticStatement) *Frame {
	return &Frame{
		frameType: SYNTHETIC_STATEMENT,
		buffer:    c.encodeExpression(stmt.Value).Encode(),
	}
}

func (c *Encoder) encodeSyntheticBase64Statement(stmt *ast.SyntheticBase64Statement) *Frame {
	return &Frame{
		frameType: SYNTHETIC_BASE64_STATEMENT,
		buffer:    c.encodeExpression(stmt.Value).Encode(),
	}
}

func (c *Encoder) encodeUnsetStatement(stmt *ast.UnsetStatement) *Frame {
	return &Frame{
		frameType: UNSET_STATEMENT,
		buffer:    c.encodeExpression(stmt.Ident).Encode(),
	}
}
