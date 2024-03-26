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

func (f *Formatter) Format(vcl *ast.VCL) (io.Reader, error) {
	buf := new(bytes.Buffer)

	var formatted string
	for i := range vcl.Statements {
		switch t := vcl.Statements[i].(type) {
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
		case *ast.PenaltyboxDeclaration:
			formatted = f.formatPenaltyboxDeclaration(t)
		case *ast.RatecounterDeclaration:
			formatted = f.formatRatecounterDeclaration(t)
		case *ast.SubroutineDeclaration:
			formatted = f.formatSubroutineDeclaration(t)
		}
		buf.WriteString(formatted + "\n")
		if i != len(vcl.Statements)-1 {
			buf.WriteString("\n")
		}
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func (f *Formatter) indent(level int) string {
	c := " " // default as whitespace
	if f.conf.IndentStyle == "tab" {
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
