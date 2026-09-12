package formatter

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/config"
)

var multiLineFeedRegex = regexp.MustCompile(`\n{3,}`)
var replace = "\n\n"

// Replace over three line-feed characters to two characters
func trimMultipleLineFeeds(lines string) string {
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

// Rewrite an inline comment as a line comment in the configured style.
// Reports false, and the comment unchanged, for anything it will not touch: a
// comment that is not "/* ... */", and one whose text spans lines, because
// converting that one would have to rewrite every line inside it.
func inlineCommentToLine(comment string, char rune) (string, bool) {
	if !strings.HasPrefix(comment, "/*") || !strings.HasSuffix(comment, "*/") || len(comment) < 4 {
		return comment, false
	}
	// Checked before trimming: a comment written with its text on the line between
	// "/*" and "*/" has both of its line feeds at the ends, and trimming first
	// would make it look like a comment written on one line.
	if strings.ContainsAny(comment, "\r\n") {
		return comment, false
	}
	text := strings.TrimSpace(comment[2 : len(comment)-2])
	// Two characters open an inline comment, so two mark the line comment it becomes.
	// That is what restyling a "//" comment does, and a converted comment that came
	// out as one "#" would be the odd one out in a file of "##".
	mark := "##"
	if char == '/' {
		mark = "//"
	}
	if text == "" {
		return mark, true
	}
	return mark + " " + text, true
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

// Format multiple line chunk string with specified indent preserving leading spaces.
func formatChunkedStringPreserveIndent(chunk, indent string) string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	for line := range strings.SplitSeq(chunk, "\n") {
		buf.WriteString(indent + line + "\n")
	}
	return buf.String()
}
