package formatter

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/config"
)

// ChunkBuffer struct reperesents limited-line chunked string from configration.
type ChunkBuffer struct {
	chunks []string
	conf   *config.FormatConfig
}

// Create ChunkBuffer pointer
func newBuffer(c *config.FormatConfig) *ChunkBuffer {
	return &ChunkBuffer{
		chunks: []string{},
		conf:   c,
	}
}

// Merge buffers
func (c *ChunkBuffer) Merge(nc *ChunkBuffer) {
	c.chunks = append(c.chunks, nc.chunks...)
}

// Write string to buffer - same as bytes.Buffer
func (c *ChunkBuffer) WriteString(s string) {
	c.chunks = append(c.chunks, s)
}

// Get "No" chunked string
func (c *ChunkBuffer) String() string {
	return strings.Join(c.chunks, "")
}

// Calculate line-chunked strings
func (c *ChunkBuffer) ChunkedString(level, offset int) string {
	// If LineWidth configuration is disabled with -1 value, simply joins strings.
	if c.conf.LineWidth < 0 {
		return c.String()
	}

	var buf bytes.Buffer

	count := offset + level*c.conf.IndentWidth
	for i, b := range c.chunks {
		// If adding next expression overflows line-width limit, insert line-feed and adjust indent
		if count+len(b) > c.conf.LineWidth {
			buf.WriteString("\n")
			buf.WriteString(indent(c.conf, level))
			if offset > 0 {
				buf.WriteString(c.offsetString(offset))
			}
			count = offset + level*c.conf.IndentWidth
		} else if i != 0 {
			buf.WriteString(" ")
			count++
		}
		buf.WriteString(b)
		count += len(b)
	}

	return strings.TrimSpace(buf.String())
}

// Padding offset string
func (c *ChunkBuffer) offsetString(offset int) string {
	ws := " " // default as whitespace
	if c.conf.IndentStyle == config.IndentStyleTab {
		ws = "\t"
	}
	return strings.Repeat(ws, offset)
}
