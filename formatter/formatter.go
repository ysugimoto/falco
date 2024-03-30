package formatter

import (
	"bytes"
	"io"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
)

type Formatter struct {
	conf *config.FormatConfig
}

func New(conf *config.FormatConfig) *Formatter {
	return &Formatter{
		conf: conf,
	}
}

func (f *Formatter) chunkBuffer() *ChunkBuffer {
	return newBuffer(f.conf)
}

func (f *Formatter) Format(vcl *ast.VCL) io.Reader {
	buf := new(bytes.Buffer)

	for i, stmt := range vcl.Statements {
		if i > 0 {
			buf.WriteString(f.lineFeed(stmt.GetMeta()))
		}
		buf.WriteString(f.formatComment(stmt.GetMeta().Leading, "\n", 0))
		var formatted string
		trailingNode := stmt

		switch t := stmt.(type) {
		case *ast.ImportStatement:
			formatted = f.formatImportStatement(t)
		case *ast.IncludeStatement:
			formatted = f.formatIncludeStatement(t)
		case *ast.AclDeclaration:
			formatted = f.formatAclDeclaration(t)
		case *ast.BackendDeclaration:
			formatted = f.formatBackendDeclaration(t)
		case *ast.DirectorDeclaration:
			formatted = f.formatDirectorDeclaration(t)
		case *ast.TableDeclaration:
			formatted = f.formatTableDeclaration(t)

		// penaltybox, ratecounter, and subroutine have trailing comment on the block statement
		case *ast.PenaltyboxDeclaration:
			formatted = f.formatPenaltyboxDeclaration(t)
			trailingNode = t.Block
		case *ast.RatecounterDeclaration:
			formatted = f.formatRatecounterDeclaration(t)
			trailingNode = t.Block
		case *ast.SubroutineDeclaration:
			formatted = f.formatSubroutineDeclaration(t)
			trailingNode = t.Block
		}
		buf.WriteString(formatted)
		buf.WriteString(f.trailing(trailingNode.GetMeta().Trailing))
		buf.WriteString("\n")
		if i != len(vcl.Statements)-1 {
			buf.WriteString("\n")
		}
	}

	return bytes.NewReader(buf.Bytes())
}

func (f *Formatter) indent(level int) string {
	c := " " // default as whitespace
	if f.conf.IndentStyle == config.IndentStyleTab {
		c = "\t"
	}
	return strings.Repeat(c, level*f.conf.IndentWidth)
}

func (f *Formatter) trailing(trailing ast.Comments) string {
	var c string

	if len(trailing) == 0 {
		return c
	}
	c += strings.Repeat(" ", f.conf.TrailingCommentWidth)
	c += f.formatComment(trailing, "", 0)
	return c
}

func (f *Formatter) lineFeed(meta *ast.Meta) string {
	if meta.PreviousEmptyLines > 0 {
		return "\n"
	}
	return ""
}
