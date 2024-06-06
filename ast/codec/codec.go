package codec

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

var encodePool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

type Codec struct {
}

func New() *Codec {
	return &Codec{}
}

func (c *Codec) Encode(stmt ast.Statement) []byte {
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

func (c *Codec) DecodeBytes(bin []byte) (ast.Statement, error) {
	return c.Decode(bytes.NewReader(bin))
}

func (c *Codec) Decode(r io.Reader) (ast.Statement, error) {
	astType, buf, err := unpack(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	switch astType {
	// Declarations
	case ACL_DECLARATION:
		return c.decodeAclDeclaration(buf)
	case BACKEND_DECLARATION:
		return c.decodeAclDeclaration(buf)
	case DIRECTOR_DECLARATION:
		return c.decodeAclDeclaration(buf)
	case PENALTYBOX_DECLARATION:
		return c.decodeAclDeclaration(buf)
	case RATECOUNTER_DECLARATION:
		return c.decodeAclDeclaration(buf)
	case SUBROUTINE_DECLARATION:
		return c.decodeAclDeclaration(buf)
	case TABLE_DECLARATION:
		return c.decodeAclDeclaration(buf)

	// Statements
	case ADD_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case BREAK_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case CALL_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case CASE_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case DECLARE_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case ELSEIF_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case ELSE_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case ERROR_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case ESI_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case FALLTHROUGH_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case FUNCTIONCALL_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case GOTO_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case GOTO_DESTINATION_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case IF_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case IMPORT_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case INCLUDE_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case LOG_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case REMOVE_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case RESTART_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case RETURN_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case SET_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case SWITCH_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case SYNTHETIC_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case SYNTHETIC_BASE64_STATEMENT:
		return c.decodeAclDeclaration(buf)
	case UNSET_STATEMENT:
		return c.decodeAclDeclaration(buf)
	default:
		return nil, errors.WithStack(fmt.Errorf("Unexpected type found: %d", astType))
	}
}
