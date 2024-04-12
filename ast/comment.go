package ast

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/token"
)

type CommentPlace int

// Basic comment placement constants.
const (
	PlaceLeading CommentPlace = iota + 1
	PlaceInfix
	PlaceTrailing
	PlaceAclBeforeName
	PlaceAclAfterName
	PlaceAclCidrAfterInverse
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
	PrefixedLineFeed bool
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
		if strings.HasPrefix(l, "@") {
			annotations = append(annotations, strings.TrimPrefix(l, "@"))
		}
	}

	return annotations
}

// CommentsMap represents map of Comments for the token.
// The key is placement, which indicates place of comment (e.g leading, infix, trailing, ...)
// Or, additional placement will exists that depeneds on the statement keywords
//
// For example:
// declare /* a */ local /* b */ var.Foo STRING;
//
// Then /* a */ comment is placed at "before_local" and /* b */ comment is placed at "after_local"
type CommentsMap map[CommentPlace]Comments

func (c CommentsMap) Get(place CommentPlace) Comments {
	if v, ok := c[place]; ok {
		return v
	}
	return Comments{}
}
