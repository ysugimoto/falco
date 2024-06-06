package codec

import (
	"bytes"

	"github.com/ysugimoto/falco/ast"
)

func (c *Codec) encodeAddStatement(stmt *ast.AddStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(stmt.Ident.Value))
	w.Write(packString(stmt.Operator.Operator))
	w.Write(c.encodeExpression(stmt.Value))

	return pack(ADD_STATEMENT, w.Bytes())
}

func (c *Codec) encodeBreakStatement(stmt *ast.BreakStatement) []byte {
	return pack(BREAK_STATEMENT, []byte{})
}

func (c *Codec) encodeCallStatement(stmt *ast.CallStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(stmt.Subroutine.Value))
	return pack(CALL_STATEMENT, w.Bytes())
}

func (c *Codec) encodeCaseStatement(stmt *ast.CaseStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	if stmt.Test != nil {
		w.Write(c.encodeInfixExpression(stmt.Test))
	} else {
		w.Write(packIdent("default"))
	}
	for _, s := range stmt.Statements {
		w.Write(c.Encode(s))
	}
	if stmt.Fallthrough {
		w.Write(pack(FALLTHROUGH_STATEMENT, []byte{}))
	}
	return pack(CASE_STATEMENT, w.Bytes())
}

func (c *Codec) encodeDeclareStatement(stmt *ast.DeclareStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(stmt.Name.Value))
	w.Write(packIdent(stmt.ValueType.Value))

	return pack(DECLARE_STATEMENT, w.Bytes())
}

func (c *Codec) encodeErrorStatement(stmt *ast.ErrorStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeExpression(stmt.Code))
	if stmt.Argument != nil {
		w.Write(c.encodeExpression(stmt.Argument))
	}

	return pack(ERROR_STATEMENT, w.Bytes())
}

func (c *Codec) encodeEsiStatement(stmt *ast.EsiStatement) []byte {
	return pack(ESI_STATEMENT, []byte{})
}

func (c *Codec) encodeFallthroughStatement(stmt *ast.FallthroughStatement) []byte {
	return pack(FALLTHROUGH_STATEMENT, []byte{})
}

func (c *Codec) encodeFunctionCallStatement(stmt *ast.FunctionCallStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(stmt.Function.Value))
	for _, arg := range stmt.Arguments {
		w.Write(c.encodeExpression(arg))
	}

	return pack(FUNCTIONCALL_STATEMENT, w.Bytes())
}

func (c *Codec) encodeGotoStatement(stmt *ast.GotoStatement) []byte {
	return pack(GOTO_STATEMENT, packIdent(stmt.Destination.Value))
}

func (c *Codec) encodeGotoDestinationStatement(stmt *ast.GotoDestinationStatement) []byte {
	return pack(GOTO_DESTINATION_STATEMENT, packIdent(stmt.Name.Value))
}

func (c *Codec) encodeIfStatement(stmt *ast.IfStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packString(stmt.Keyword))
	w.Write(c.encodeExpression(stmt.Condition))
	for _, s := range stmt.Consequence.Statements {
		w.Write(c.Encode(s))
	}
	w.Write(end())
	for _, a := range stmt.Another {
		w.Write(c.encodeIfStatement(a))
	}
	if stmt.Alternative != nil {
		alt := encodePool.Get().(*bytes.Buffer)
		for _, s := range stmt.Alternative.Consequence.Statements {
			alt.Write(c.Encode(s))
		}
		w.Write(pack(ELSE_STATEMENT, alt.Bytes()))
		encodePool.Put(alt)
	}

	return pack(IF_STATEMENT, w.Bytes())
}

func (c *Codec) encodeImportStatement(stmt *ast.ImportStatement) []byte {
	return pack(IMPORT_STATEMENT, packIdent(stmt.Name.Value))
}

func (c *Codec) encodeIncludeStatement(stmt *ast.IncludeStatement) []byte {
	return pack(INCLUDE_STATEMENT, packIdent(stmt.Module.Value))
}

func (c *Codec) encodeLogStatement(stmt *ast.LogStatement) []byte {
	return pack(LOG_STATEMENT, c.encodeExpression(stmt.Value))
}

func (c *Codec) encodeRemoveStatement(stmt *ast.RemoveStatement) []byte {
	return pack(REMOVE_STATEMENT, packIdent(stmt.Ident.Value))
}

func (c *Codec) encodeRestartStatement(stmt *ast.RestartStatement) []byte {
	return pack(RESTART_STATEMENT, []byte{})
}

func (c *Codec) encodeReturnStatement(stmt *ast.ReturnStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	if stmt.ReturnExpression != nil {
		w.Write(packBoolean(stmt.HasParenthesis))
		w.Write(c.encodeExpression(stmt.ReturnExpression))
	}
	return pack(RETURN_STATEMENT, w.Bytes())
}

func (c *Codec) encodeSetStatement(stmt *ast.SetStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(packIdent(stmt.Ident.Value))
	w.Write(packString(stmt.Operator.Operator))
	w.Write(c.encodeExpression(stmt.Value))

	return pack(SET_STATEMENT, w.Bytes())
}

func (c *Codec) encodeSwitchStatement(stmt *ast.SwitchStatement) []byte {
	w := encodePool.Get().(*bytes.Buffer)
	defer encodePool.Put(w)
	w.Reset()

	w.Write(c.encodeExpression(stmt.Control.Expression))
	for _, sc := range stmt.Cases {
		w.Write(c.encodeCaseStatement(sc))
	}
	w.Write(packInteger(int64(stmt.Default)))

	return pack(SWITCH_STATEMENT, w.Bytes())
}

func (c *Codec) encodeSyntheticStatement(stmt *ast.SyntheticStatement) []byte {
	return pack(SYNTHETIC_STATEMENT, c.encodeExpression(stmt.Value))
}

func (c *Codec) encodeSyntheticBase64Statement(stmt *ast.SyntheticBase64Statement) []byte {
	return pack(SYNTHETIC_BASE64_STATEMENT, c.encodeExpression(stmt.Value))
}

func (c *Codec) encodeUnsetStatement(stmt *ast.UnsetStatement) []byte {
	return pack(UNSET_STATEMENT, packIdent(stmt.Ident.Value))
}
