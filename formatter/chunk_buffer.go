package formatter

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/config"
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
	Operator
	Group
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

// ChunkBuffer struct reperesents limited-line chunked string from configration.
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
	var buf bytes.Buffer

	for i := range c.chunks {
		buf.WriteString(c.chunks[i].buffer)
		if c.chunks[i].isLineComment() {
			buf.WriteString("\n")
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

	var buf bytes.Buffer

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
		// group operator
		case Group:
			// If group operator, inside expressions should be printed on the same line
			if next := c.nextChunk(); next != nil {
				buf.WriteString(c.chunkGroupOperator(state, next))
			}
		// infix operator
		case Operator:
			// Or, the operator is the member os mustSingleOperators, the expression must be printed on the same line
			if _, ok := mustSingleOperators[chunk.buffer]; ok {
				buf.WriteString(c.chunkInfixOperator(state, chunk))
				continue
			}
			buf.WriteString(c.chunkString(state, chunk.buffer))
		// Otherwise (token), create chunk string
		default:
			buf.WriteString(c.chunkString(state, chunk.buffer))
		}
	}
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
	var buf bytes.Buffer

	if !state.isHead() {
		buf.WriteString(c.nextLine(state))
	}
	buf.WriteString(chunk.buffer)
	buf.WriteString(c.nextLine(state))
	state.reset()

	return buf.String()
}

// chunkGroupOperator() returns chunk group expression string
func (c *ChunkBuffer) chunkGroupOperator(state *ChunkState, chunk *Chunk) string {
	expr := chunk.buffer

	for {
		next := c.nextChunk()
		if next == nil {
			return c.chunkString(state, "("+expr+")")
		}

		switch {
		case next.isLineComment():
			expr += next.buffer
			expr += c.nextLine(state)
			state.reset()
		case next.buffer == ")":
			return c.chunkString(state, "("+expr+")")
		default:
			expr += " " + next.buffer
		}
	}
}

// chunkInfixOperator() returns chunk infix expression string
func (c *ChunkBuffer) chunkInfixOperator(state *ChunkState, chunk *Chunk) string {
	expr := chunk.buffer

	for {
		next := c.nextChunk()
		if next == nil {
			return c.chunkString(state, expr)
		}

		switch next.Type {
		case Comment:
			if next.isLineComment() {
				expr += next.buffer
				expr += c.nextLine(state)
				state.reset()
				continue
			}
			expr += " " + next.buffer
		default:
			expr += " " + next.buffer
			return c.chunkString(state, expr)
		}
	}
}

// chunkString() returns chunked string
func (c *ChunkBuffer) chunkString(state *ChunkState, expr string) string {
	var buf bytes.Buffer
	var prefix string

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
