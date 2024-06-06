package codec

import (
	"bytes"
	"sync"

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

func (c *Encoder) Encode(stmt ast.Statement) []byte {
	var bin []byte

	switch t := stmt.(type) {
	// Declarations
	case *ast.AclDeclaration:
		bin = c.encodeAclDeclaration(t)
	case *ast.BackendDeclaration:
		bin = c.encodeBackendDeclaration(t)
	case *ast.DirectorDeclaration:
		bin = c.encodeDirectorDeclaration(t)
	case *ast.PenaltyboxDeclaration:
		bin = c.encodePenaltyboxDelcaration(t)
	case *ast.RatecounterDeclaration:
		bin = c.encodeRatecounterDeclaration(t)
	case *ast.SubroutineDeclaration:
		bin = c.encodeSubroutineDeclaration(t)
	case *ast.TableDeclaration:
		bin = c.encodeTableDeclaration(t)

	// Statements
	case *ast.AddStatement:
		bin = c.encodeAddStatement(t)
	case *ast.BreakStatement:
		bin = c.encodeBreakStatement(t)
	case *ast.CallStatement:
		bin = c.encodeCallStatement(t)
	case *ast.CaseStatement:
		bin = c.encodeCaseStatement(t)
	case *ast.DeclareStatement:
		bin = c.encodeDeclareStatement(t)
	case *ast.ErrorStatement:
		bin = c.encodeErrorStatement(t)
	case *ast.EsiStatement:
		bin = c.encodeEsiStatement(t)
	case *ast.FallthroughStatement:
		bin = c.encodeFallthroughStatement(t)
	case *ast.FunctionCallStatement:
		bin = c.encodeFunctionCallStatement(t)
	case *ast.GotoStatement:
		bin = c.encodeGotoStatement(t)
	case *ast.GotoDestinationStatement:
		bin = c.encodeGotoDestinationStatement(t)
	case *ast.IfStatement:
		bin = c.encodeIfStatement(t)
	case *ast.ImportStatement:
		bin = c.encodeImportStatement(t)
	case *ast.IncludeStatement:
		bin = c.encodeIncludeStatement(t)
	case *ast.LogStatement:
		bin = c.encodeLogStatement(t)
	case *ast.RemoveStatement:
		bin = c.encodeRemoveStatement(t)
	case *ast.RestartStatement:
		bin = c.encodeRestartStatement(t)
	case *ast.ReturnStatement:
		bin = c.encodeReturnStatement(t)
	case *ast.SetStatement:
		bin = c.encodeSetStatement(t)
	case *ast.SwitchStatement:
		bin = c.encodeSwitchStatement(t)
	case *ast.SyntheticStatement:
		bin = c.encodeSyntheticStatement(t)
	case *ast.SyntheticBase64Statement:
		bin = c.encodeSyntheticBase64Statement(t)
	case *ast.UnsetStatement:
		bin = c.encodeUnsetStatement(t)
	}

	return bin
}
