package codec

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

var encodePool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

type Encoder struct {
}

func NewEncoder() *Encoder {
	return &Encoder{}
}

func (c *Encoder) Encodes(statements []ast.Statement) ([]byte, error) {
	buf := encodePool.Get().(*bytes.Buffer) // nolint:errcheck
	defer encodePool.Put(buf)
	buf.Reset()

	for i := range statements {
		frame, err := c.encode(statements[i])
		if err != nil {
			return nil, errors.WithStack(err)
		}

		buf.Write(frame.Encode())
	}
	buf.Write(fin())
	return buf.Bytes(), nil
}

func (c *Encoder) Encode(stmt ast.Statement) ([]byte, error) {
	frame, err := c.encode(stmt)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	bin := frame.Encode()
	bin = append(bin, fin()...)
	return bin, nil
}

func (c *Encoder) encode(stmt ast.Statement) (*Frame, error) {
	var frame *Frame

	switch t := stmt.(type) {
	// Declarations
	case *ast.AclDeclaration:
		frame = c.encodeAclDeclaration(t)
	case *ast.BackendDeclaration:
		frame = c.encodeBackendDeclaration(t)
	case *ast.DirectorDeclaration:
		frame = c.encodeDirectorDeclaration(t)
	case *ast.PenaltyboxDeclaration:
		frame = c.encodePenaltyboxDelcaration(t)
	case *ast.RatecounterDeclaration:
		frame = c.encodeRatecounterDeclaration(t)
	case *ast.SubroutineDeclaration:
		frame = c.encodeSubroutineDeclaration(t)
	case *ast.TableDeclaration:
		frame = c.encodeTableDeclaration(t)

	// Statements
	case *ast.AddStatement:
		frame = c.encodeAddStatement(t)
	case *ast.BlockStatement:
		frame = c.encodeBlockStatement(t)
	case *ast.BreakStatement:
		frame = c.encodeBreakStatement()
	case *ast.CallStatement:
		frame = c.encodeCallStatement(t)
	case *ast.CaseStatement:
		frame = c.encodeCaseStatement(t)
	case *ast.DeclareStatement:
		frame = c.encodeDeclareStatement(t)
	case *ast.ErrorStatement:
		frame = c.encodeErrorStatement(t)
	case *ast.EsiStatement:
		frame = c.encodeEsiStatement()
	case *ast.FallthroughStatement:
		frame = c.encodeFallthroughStatement()
	case *ast.FunctionCallStatement:
		frame = c.encodeFunctionCallStatement(t)
	case *ast.GotoStatement:
		frame = c.encodeGotoStatement(t)
	case *ast.GotoDestinationStatement:
		frame = c.encodeGotoDestinationStatement(t)
	case *ast.IfStatement:
		frame = c.encodeIfStatement(t)
	case *ast.ImportStatement:
		frame = c.encodeImportStatement(t)
	case *ast.IncludeStatement:
		frame = c.encodeIncludeStatement(t)
	case *ast.LogStatement:
		frame = c.encodeLogStatement(t)
	case *ast.RemoveStatement:
		frame = c.encodeRemoveStatement(t)
	case *ast.RestartStatement:
		frame = c.encodeRestartStatement()
	case *ast.ReturnStatement:
		frame = c.encodeReturnStatement(t)
	case *ast.SetStatement:
		frame = c.encodeSetStatement(t)
	case *ast.SwitchStatement:
		frame = c.encodeSwitchStatement(t)
	case *ast.SyntheticStatement:
		frame = c.encodeSyntheticStatement(t)
	case *ast.SyntheticBase64Statement:
		frame = c.encodeSyntheticBase64Statement(t)
	case *ast.UnsetStatement:
		frame = c.encodeUnsetStatement(t)
	default:
		return nil, fmt.Errorf("Unknown node provided: %s", stmt.GetMeta().Token.Literal)
	}
	return frame, nil
}
