package formatter

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/v2/config"
)

// This map is used for the expression can be chunked or not.
// Following operators must be printed on a single line, otherwise VCL will cause syntax error.
var mustSingleOperators = map[string]struct{}{
	"==": {},
	"!=": {},
	"~":  {},
	"!~": {},
	">":  {},
	"<":  {},
	">=": {},
	"<=": {},
}

type ChunkType int

const (
	Token ChunkType = iota + 1
	Comment
	Infix
	Group
	Prefix
)

// Chunk struct represents a piece of expression token
type Chunk struct {
	buffer string
	Type   ChunkType
}

// isLineComment() returns true if chunk buffer is line comment that start with "#" or "//"
func (c *Chunk) isLineComment() bool {
	if c.Type != Comment {
		return false
	}

	prefix := make([]byte, 2)
	prefix[0] = c.buffer[0]
	if len(c.buffer) > 1 {
		prefix[1] = c.buffer[1]
	}
	return string(prefix) != "/*"
}

// ChunkBuffer struct represents limited-line chunked string from configuration.
type ChunkBuffer struct {
	chunks []*Chunk
	conf   *config.FormatConfig
	index  int
}

// Create ChunkBuffer pointer
func newBuffer(c *config.FormatConfig) *ChunkBuffer {
	return &ChunkBuffer{
		chunks: []*Chunk{},
		conf:   c,
		index:  -1,
	}
}

// Get next chunk
func (c *ChunkBuffer) nextChunk() *Chunk {
	if c.index+1 > len(c.chunks)-1 {
		return nil
	}
	c.index++
	return c.chunks[c.index]
}

// Get peek chunk
func (c *ChunkBuffer) peekChunk(i int) *Chunk {
	if c.index+i > len(c.chunks)-1 {
		return nil
	}
	return c.chunks[c.index+i]
}

// Append buffers
func (c *ChunkBuffer) Append(nc *ChunkBuffer) {
	c.chunks = append(c.chunks, nc.chunks...)
}

// Write buffer to buffer with ChunkType
func (c *ChunkBuffer) Write(s string, t ChunkType) {
	c.chunks = append(c.chunks, &Chunk{
		buffer: s,
		Type:   t,
	})
}

// Get "No" chunked string
func (c *ChunkBuffer) String() string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	for i := range c.chunks {
		buf.WriteString(c.chunks[i].buffer)
		if c.chunks[i].isLineComment() {
			buf.WriteString("\n")
		} else if i < len(c.chunks)-1 && c.chunks[i].Type != Prefix {
			buf.WriteString(" ")
		}
	}

	return buf.String()
}

// ChunkState represents generating chunk strings
type ChunkState struct {
	lineWidth int
	level     int
	offset    int
	head      int
	count     int
}

// isHead() returns true is current state is the head of line
func (s *ChunkState) isHead() bool {
	return s.count == s.head
}

// Reset state
func (s *ChunkState) reset() {
	s.count = s.head
}

// Calculate line-chunked strings
func (c *ChunkBuffer) ChunkedString(level, offset int) string {
	// If LineWidth configuration is disabled with -1 value, simply joins strings.
	if c.conf.LineWidth < 0 {
		return c.String()
	}

	state := &ChunkState{
		lineWidth: c.conf.LineWidth,
		level:     level,
		offset:    offset,
		head:      offset + level*c.conf.IndentWidth,
		count:     offset + level*c.conf.IndentWidth,
	}

	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	for {
		chunk := c.nextChunk()
		if chunk == nil {
			return strings.TrimSpace(buf.String())
		}

		switch chunk.Type {
		case Comment:
			// "//", "#" comment, need to print next line
			if chunk.isLineComment() {
				buf.WriteString(c.chunkLineComment(state, chunk))
				continue
			}
			buf.WriteString(c.chunkString(state, chunk.buffer))
		// prefix and group operator
		case Prefix, Group:
			// Both take an operand, and the operand may be a group, which may hold
			// another one. Read the whole thing and print it as a single chunk: the
			// operand of a prefix operator cannot be separated from it, and inside a
			// group expressions should be printed on the same line.
			buf.WriteString(c.chunkString(state, c.readOperand(state, chunk)))
		// infix operator
		case Infix:
			buf.WriteString(c.chunkString(state, chunk.buffer))
		// Otherwise (token), create chunk string
		default:
			// Pre-combine infix operator that must be placed on the same line
			chunk.buffer += c.combineInfixChunk()
			buf.WriteString(c.chunkString(state, chunk.buffer))
		}
	}
}

// Read peek chunk and combine if the chunk is placed on the same line
func (c *ChunkBuffer) combineInfixChunk() string {
	var peek *Chunk
	var expr bytes.Buffer
	var index int

	for {
		index++
		peek = c.peekChunk(index)
		if peek == nil {
			return ""
		}
		switch peek.Type {
		// If peek chunk is Infix, it may combine
		case Infix:
			goto OUT
		// If peek chunk is Comment, should be combined and look up next chunk
		case Comment:
			expr.WriteString(" " + peek.buffer)
		default:
			return ""
		}
	}
OUT:

	// Infix operator
	_, ok := mustSingleOperators[peek.buffer]
	if !ok {
		return ""
	}
	expr.WriteString(" " + peek.buffer)

	// Skip infix comments
	for {
		index++
		peek = c.peekChunk(index)
		if peek == nil {
			return ""
		}
		if peek.Type == Comment {
			expr.WriteString(" " + peek.buffer)
			continue
		}
		break
	}
	// Finally, add token buffer
	expr.WriteString(" " + peek.buffer)

	// Forward index position to be read
	for index > 0 {
		c.nextChunk()
		index--
	}

	return expr.String()
}

// nextLine() returns line feed and indent string
func (c *ChunkBuffer) nextLine(state *ChunkState) string {
	out := "\n" + indent(c.conf, state.level)
	if state.offset > 0 {
		out += c.offsetString(state.offset)
	}
	return out
}

// chunkLineComment() returns chunk string of line comment
func (c *ChunkBuffer) chunkLineComment(state *ChunkState, chunk *Chunk) string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	// if !state.isHead() {
	// 	buf.WriteString(c.nextLine(state))
	// }
	buf.Reset()
	buf.WriteString(" " + chunk.buffer)
	buf.WriteString(c.nextLine(state))
	state.reset()

	return buf.String()
}

// readOperand() returns the string of the operand that starts at the given chunk,
// consuming the chunks it is made of. An opening parenthesis takes everything up to
// the one that closes it, and a prefix operator takes the operand that follows it.
func (c *ChunkBuffer) readOperand(state *ChunkState, chunk *Chunk) string {
	switch {
	case chunk.Type == Group && chunk.buffer == "(":
		return c.readGroup(state)
	case chunk.Type == Prefix:
		if next := c.nextChunk(); next != nil {
			return chunk.buffer + c.readOperand(state, next)
		}
	}
	return chunk.buffer
}

// readGroup() returns the string of a group whose opening parenthesis has already
// been consumed, parentheses included. It reads operands rather than chunks, so a
// nested group is read whole and the parenthesis this stops at is the matching one.
// Scanning flat stops at the first one instead, which leaves the outer closing
// parentheses behind as chunks that nothing prints, and VCL that falco cannot parse
// back is the result.
func (c *ChunkBuffer) readGroup(state *ChunkState) string {
	var expr string

	for {
		next := c.nextChunk()
		if next == nil {
			return "(" + expr
		}

		switch {
		case next.Type == Group && next.buffer == ")":
			return "(" + expr + ")"
		case next.isLineComment():
			expr += next.buffer
			expr += c.nextLine(state)
			state.reset()
		default:
			operand := c.readOperand(state, next)
			if expr == "" {
				expr = operand
			} else {
				expr += " " + operand
			}
		}
	}
}

// chunkString() returns chunked string
func (c *ChunkBuffer) chunkString(state *ChunkState, expr string) string {
	var prefix string
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	if !state.isHead() {
		prefix = " "
	}

	if state.count+len(prefix+expr) > state.lineWidth {
		buf.WriteString(c.nextLine(state))
		state.reset()
		prefix = ""
	}
	buf.WriteString(prefix + expr)
	state.count += len(prefix + expr)

	return buf.String()
}

// Padding offset string
func (c *ChunkBuffer) offsetString(offset int) string {
	ws := " " // default as whitespace
	if c.conf.IndentStyle == config.IndentStyleTab {
		ws = "\t"
	}
	return strings.Repeat(ws, offset)
}
