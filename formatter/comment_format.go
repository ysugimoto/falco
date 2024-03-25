package formatter

import (
	"bytes"

	"github.com/ysugimoto/falco/ast"
)

func (f *Formatter) formatComment(comments ast.Comments, sep string, level int) string {
	if len(comments) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range comments {
		buf.WriteString(f.indent(level) + comments[i].String())
		buf.WriteString(sep)
	}

	return buf.String()
}
