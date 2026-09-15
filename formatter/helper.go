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

// Opening of a long string literal, capturing the delimiter that closes it.
var longStringOpenRegex = regexp.MustCompile(`^\{([0-9A-Za-z_]*)"`)

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

// Split a chunk string into lines, reporting for each one whether it begins
// inside a long string literal. A long string keeps every byte between its
// delimiters, line feeds and leading whitespace included, so those lines are the
// string's own value and not the formatter's layout.
func splitChunkLines(chunk string) ([]string, []bool) {
	var (
		lines    []string
		inString []bool
		line     strings.Builder
	)

	// State while scanning: inside a short string, inside a long string with the
	// delimiter that will close it, or inside a comment.
	var (
		short     bool
		long      bool
		delimiter string
		comment   string
		// Whether the line being collected began inside a long string, which is
		// not the same as whether the scan is inside one now: the line that opens
		// a long string is still the formatter's own.
		began bool
	)

	cut := func() {
		lines = append(lines, line.String())
		inString = append(inString, began)
		line.Reset()
		began = long
	}

	for i := 0; i < len(chunk); i++ {
		switch {
		case chunk[i] == '\n':
			cut()
			if comment == "\n" {
				comment = ""
			}
			continue
		case comment != "":
			if comment == "*/" && strings.HasPrefix(chunk[i:], "*/") {
				line.WriteString("*/")
				comment = ""
				i++
				continue
			}
		case short:
			if chunk[i] == '"' {
				short = false
			}
		case long:
			// A long string ends at `"` followed by its delimiter and `}`.
			if chunk[i] == '"' && strings.HasPrefix(chunk[i+1:], delimiter+"}") {
				line.WriteString(`"` + delimiter + "}")
				i += len(delimiter) + 1
				long = false
				continue
			}
		case strings.HasPrefix(chunk[i:], "/*"):
			comment = "*/"
		case strings.HasPrefix(chunk[i:], "//"), chunk[i] == '#':
			comment = "\n"
		case chunk[i] == '"':
			short = true
		case chunk[i] == '{':
			if m := longStringOpenRegex.FindStringSubmatch(chunk[i:]); m != nil {
				delimiter = m[1]
				long = true
				line.WriteString(m[0])
				i += len(m[0]) - 1
				continue
			}
		}
		line.WriteByte(chunk[i])
	}
	cut()

	return lines, inString
}

// Format multiple line chunk string with specified indent
func formatChunkedString(chunk, indent string) string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	lines, inString := splitChunkLines(chunk)
	for i, line := range lines {
		// A line that begins inside a long string is that string's own value.
		if inString[i] {
			buf.WriteString(line + "\n")
			continue
		}
		buf.WriteString(indent + strings.TrimSpace(line) + "\n")
	}
	return buf.String()
}

// Format multiple line chunk string with specified indent preserving leading spaces.
func formatChunkedStringPreserveIndent(chunk, indent string) string {
	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	lines, inString := splitChunkLines(chunk)
	for i, line := range lines {
		if inString[i] {
			buf.WriteString(line + "\n")
			continue
		}
		buf.WriteString(indent + line + "\n")
	}
	return buf.String()
}
