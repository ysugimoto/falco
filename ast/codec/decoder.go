package codec

import (
	"bufio"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

type Decoder struct {
	r   *bufio.Reader
	fin *Frame
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		r: bufio.NewReader(r),
	}
}

func (c *Decoder) nextFrame() *Frame {
	if c.fin != nil {
		return c.fin
	}

	buf := framePool.Get().(*[]byte) // nolint:errcheck
	defer framePool.Put(buf)

	if _, err := io.LimitReader(c.r, 1).Read(*buf); err != nil {
		return &Frame{
			frameType: UNKNOWN,
			size:      0,
		}
	}
	frameType := FrameType((*buf)[0])
	switch frameType {
	case END:
		return &Frame{
			frameType: END,
			size:      0,
		}
	case FIN:
		c.fin = &Frame{
			frameType: FIN,
			size:      0,
		}
		return c.fin
	}

	if _, err := io.LimitReader(c.r, 2).Read(*buf); err != nil {
		return &Frame{
			frameType: UNKNOWN,
			size:      0,
		}
	}
	upper := int((*buf)[0])
	size := (upper << 8) | int((*buf)[1])

	return &Frame{
		frameType: frameType,
		size:      size,
	}
}

func (c *Decoder) peekFrameIs(t FrameType) bool {
	return c.peekFrame().Type() == t
}

func (c *Decoder) peekFrame() *Frame {
	b, err := c.r.Peek(1)
	if err != nil {
		return &Frame{
			frameType: UNKNOWN,
			size:      0,
		}
	}
	frameType := FrameType(b[0])
	if frameType == END || frameType == FIN {
		return &Frame{
			frameType: frameType,
			size:      0,
		}
	}

	b, err = c.r.Peek(3)
	if err != nil {
		return &Frame{
			frameType: UNKNOWN,
			size:      0,
		}
	}
	upper := int(b[1])
	size := (upper << 8) | int(b[2])

	return &Frame{
		frameType: FrameType(b[0]),
		size:      size,
	}
}

func (c *Decoder) Decode() ([]ast.Statement, error) {
	var statements []ast.Statement

	for {
		frame := c.nextFrame()
		if frame.Type() == FIN {
			break
		}
		stmt, err := c.decode(frame)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		statements = append(statements, stmt)
	}

	return statements, nil
}

func (c *Decoder) decode(frame *Frame) (ast.Statement, error) {
	switch frame.Type() {
	// Declarations
	case ACL_DECLARATION:
		return c.decodeAclDeclaration()
	case BACKEND_DECLARATION:
		return c.decodeBackendDeclaration()
	case DIRECTOR_DECLARATION:
		return c.decodeDirectorDeclaration()
	case PENALTYBOX_DECLARATION:
		return c.decodePenaltyboxDeclaration()
	case RATECOUNTER_DECLARATION:
		return c.decodeRatecounterDeclaration()
	case SUBROUTINE_DECLARATION:
		return c.decodeSubroutineDeclaration()
	case TABLE_DECLARATION:
		return c.decodeTableDeclaration()

	// Statements
	case ADD_STATEMENT:
		return c.decodeAddStatement()
	case BLOCK_STATEMENT:
		return c.decodeBlockStatement()
	case BREAK_STATEMENT:
		return c.decodeBreakStatement()
	case CALL_STATEMENT:
		return c.decodeCallStatement()
	case CASE_STATEMENT:
		return c.decodeCaseStatement()
	case DECLARE_STATEMENT:
		return c.decodeDeclareStatement()
	case ERROR_STATEMENT:
		return c.decodeErrorStatement()
	case ESI_STATEMENT:
		return c.decodeEsiStatement()
	case FALLTHROUGH_STATEMENT:
		return c.decodeFallthroughStatement()
	case FUNCTIONCALL_STATEMENT:
		return c.decodeFunctionCallStatement()
	case GOTO_STATEMENT:
		return c.decodeGotoStatement()
	case GOTO_DESTINATION_STATEMENT:
		return c.decodeGotoDestionationStatement()
	case IF_STATEMENT:
		return c.decodeIfStatement()
	case IMPORT_STATEMENT:
		return c.decodeImportStatement()
	case INCLUDE_STATEMENT:
		return c.decodeIncludeStatement()
	case LOG_STATEMENT:
		return c.decodeLogStatement()
	case REMOVE_STATEMENT:
		return c.decodeRemoveStatement()
	case RESTART_STATEMENT:
		return c.decodeRestartStatement()
	case RETURN_STATEMENT:
		return c.decodeReturnStatement()
	case SET_STATEMENT:
		return c.decodeSetStatement()
	case SWITCH_STATEMENT:
		return c.decodeSwitchStatement()
	case SYNTHETIC_STATEMENT:
		return c.decodeSyntheticStatement()
	case SYNTHETIC_BASE64_STATEMENT:
		return c.decodeSyntheticBase64Statement()
	case UNSET_STATEMENT:
		return c.decodeUnsetStatement()
	default:
		return nil, errors.WithStack(fmt.Errorf("Unexpected frame found: %s", frame.String()))
	}
}
