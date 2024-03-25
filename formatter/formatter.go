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
		case *ast.AclDeclaration:
			formatted = f.formatAclDeclaration(t)
		case *ast.BackendDeclaration:
			formatted = f.formatBackendDeclaration(t)
		case *ast.DirectorDeclaration:
			formatted = f.formatDirectorDeclaration(t)
		case *ast.TableDeclaration:
			formatted = f.formatTableDeclaration(t)
		}
		buf.WriteString(formatted + "\n")
		if i != len(vcl.Statements)-1 {
			buf.WriteString("\n")
		}
	}

	return bytes.NewReader(buf.Bytes()), nil

	// for {
	// 	tok := f.l.NextToken()

	// 	switch tok.Type {
	// 	case token.ACL:
	// 		formatted, err = f.formatAclDeclaration(conf)
	// 	// case token.IMPORT:
	// 	// 	formatted, err = f.formatImportStatement(conf)
	// 	// case token.INCLUDE:
	// 	// 	formatted, err = f.formatIncludeStatement(conf)
	// 	case token.BACKEND:
	// 		formatted, err = f.formatBackendDeclaration(conf)
	// 	// case token.DIRECTOR:
	// 	// 	formatted, err = f.formatDirectorDeclaration(conf)
	// 	// case token.TABLE:
	// 	// 	formatted, err = f.formatTableDeclaration(conf)
	// 	// case token.SUBROUTINE:
	// 	// 	formatted, err = f.formatSubroutineDeclaration(conf)
	// 	// case token.PENALTYBOX:
	// 	// 	formatted, err = f.formatPenaltyboxDeclaration(conf)
	// 	// case token.RATECOUNTER:
	// 	// 	formatted, err = f.formatRatecounterDeclaration(conf)
	// 	// case token.COMMENT:
	// 	// 	formatted, err = f.formatComment(conf, token)
	// 	case token.ILLEGAL:
	// 		return nil, errors.New("Invalid token found")
	// 	case token.EOF:
	// 		return bytes.NewReader(buf.Bytes()), nil
	// 	default:
	// 		// LF, WHITESPACES, ETC
	// 		formatted = tok.Literal
	// 	}
	// 	if err != nil {
	// 		return nil, errors.WithStack(err)
	// 	}
	// 	buf.WriteString(formatted)
	// }
}

func (f *Formatter) indent(level int) string {
	c := " " // default as whitespace
	if f.conf.IndentStyle == "tab" {
		c = "\t"
	}
	return strings.Repeat(c, level*f.conf.IndentWidth)
}
