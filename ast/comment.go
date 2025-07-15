package ast

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/token"
)

type Comment struct {
	Token token.Token
	Value string
	// PrefixedLineFeed represents the previous token of this comment is token.LF.
	// For example:
	//
	// ...some statements...
	// } // comment with PrefixedLineFeed: false
	// ----
	// ...some statements ...
	// }
	// // comment with PrefixedLineFeed: true
	// This flag is used for parsing trailing comment,
	// If this flag is false, it should be treated as trailing comment
	// because the comment presents on the same line.
	// Otherwise, this flag is true, it should be the leading comment for a next token.
	PrefixedLineFeed   bool
	PreviousEmptyLines int
}

func (c *Comment) String() string {
	return c.Value
}

type Comments []*Comment

func (c Comments) String() string {
	if len(c) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range c {
		buf.WriteString(c[i].String())
	}

	return buf.String()
}

func (c *Comments) Annotations() []string {
	var annotations []string

	lines := strings.Split(c.String(), "\n")
	for i := range lines {
		l := strings.TrimLeft(lines[i], " */#")
		if annotation, found := strings.CutPrefix(l, "@"); found {
			annotations = append(annotations, annotation)
		}
	}

	return annotations
}
