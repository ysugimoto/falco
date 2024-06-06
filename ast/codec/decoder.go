package codec

import (
	"bufio"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

type Decoder struct {
}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (c *Decoder) peekTypeIs(r *bufio.Reader, t AstType) bool {
	b, err := r.Peek(1)
	if err != nil {
		return false
	}
	return AstType(b[0]) == t
}

func (c *Decoder) Decode(r io.Reader) (ast.Statement, error) {
	astType, reader, err := unpack(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	switch astType {
	// Declarations
	case ACL_DECLARATION:
		return c.decodeAclDeclaration(reader)
	case BACKEND_DECLARATION:
		return c.decodeAclDeclaration(reader)
	case DIRECTOR_DECLARATION:
		return c.decodeAclDeclaration(reader)
	case PENALTYBOX_DECLARATION:
		return c.decodeAclDeclaration(reader)
	case RATECOUNTER_DECLARATION:
		return c.decodeAclDeclaration(reader)
	case SUBROUTINE_DECLARATION:
		return c.decodeAclDeclaration(reader)
	case TABLE_DECLARATION:
		return c.decodeAclDeclaration(reader)

	// Statements
	case ADD_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case BREAK_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case CALL_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case CASE_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case DECLARE_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case ELSEIF_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case ELSE_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case ERROR_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case ESI_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case FALLTHROUGH_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case FUNCTIONCALL_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case GOTO_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case GOTO_DESTINATION_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case IF_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case IMPORT_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case INCLUDE_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case LOG_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case REMOVE_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case RESTART_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case RETURN_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case SET_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case SWITCH_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case SYNTHETIC_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case SYNTHETIC_BASE64_STATEMENT:
		return c.decodeAclDeclaration(reader)
	case UNSET_STATEMENT:
		return c.decodeAclDeclaration(reader)
	default:
		return nil, errors.WithStack(fmt.Errorf("Unexpected type found: %d", astType))
	}
	return nil, errors.New("Not Implemented")
}
