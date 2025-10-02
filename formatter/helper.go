package formatter

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
)

var multiLineFeedRegex = regexp.MustCompile(`\n{3,}`)
var replace = "\n\n"

// Replace over three line-feed characters to two characters
func trimMutipleLineFeeds(lines string) string {
	return multiLineFeedRegex.ReplaceAllString(lines, replace)
}

// Calculate indent strings from configuration
func indent(conf *config.FormatConfig, level int) string {
	c := " " // default as whitespace
	if conf.IndentStyle == config.IndentStyleTab {
		c = "\t"
	}
	return strings.Repeat(c, level*conf.IndentWidth)
}

// Format comment line (ignore inline comment)
func formatCommentCharacter(comment string, char rune) string {
	bs := []rune(comment)
	// Sharp-style comment
	switch bs[0] {
	case '#':
		for i := range bs {
			if bs[i] != '#' {
				break
			}
			bs[i] = char
		}
	// Slash-style comment
	case '/':
		// Check inline comment like /* ... */ and return without replacing if so
		if len(bs) < 2 || bs[1] == '*' {
			return string(bs)
		}
		for i := range bs {
			if bs[i] != '/' {
				break
			}
			bs[i] = char
		}
	}

	return string(bs)
}

// Return comment is inline comment that has "/* ... */" syntax
func isInlineComment(comments ast.Comments) bool {
	if len(comments) == 0 {
		return true
	}
	return strings.HasPrefix(comments[0].Value, "/*")
}

// Get latest line offset (character length) from current buffer
func getLineOffset(b *bytes.Buffer) int {
	s := b.String()
	if p := strings.LastIndex(s, "\n"); p >= 0 {
		return len(s[p:])
	}
	return len(s)
}

// Format multiple line chunk string with specified indent
func formatChunkedString(chunk, indent string) string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	for line := range strings.SplitSeq(chunk, "\n") {
		buf.WriteString(indent + strings.TrimSpace(line) + "\n")
	}
	return buf.String()
}
