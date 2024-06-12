package formatter

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
)

var bufferPool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

// Formatter is struct for formatting input VCL.
type Formatter struct {
	// Defined at config package, all built-in formatting rules includes with default values
	conf *config.FormatConfig

	// statful formatting - flag for formatting inside functional subroutine.
	// If this flag turns on, the return statement MUST return the subroutine return type, not a state
	// so it should not wrap the parenthesis even if configuration is true.
	isFunctionalSubroutine bool
}

// Create Formatter pointer
func New(conf *config.FormatConfig) *Formatter {
	return &Formatter{
		conf: conf,
	}
}

// Create ChunkBuffer by passing provided configuration
func (f *Formatter) chunkBuffer() *ChunkBuffer {
	return newBuffer(f.conf)
}

// Do formatting.
// Note that argument of vcl must be an AST-ed tree that is created by parser package.
// It means parser should have all information about input VCL (comment, empty lines, etc...)
// And of course input VCL must have a valid syntax.
func (f *Formatter) Format(vcl *ast.VCL) io.Reader {
	decls := Declarations{}

	for _, stmt := range vcl.Statements {
		var decl *Declaration
		trailingNode := stmt

		switch t := stmt.(type) {
		case *ast.ImportStatement:
			decl = &Declaration{
				Type:   Import,
				Buffer: f.formatImportStatement(t),
			}
		case *ast.IncludeStatement:
			decl = &Declaration{
				Type:   Include,
				Buffer: f.formatIncludeStatement(t),
			}
		case *ast.AclDeclaration:
			decl = f.formatAclDeclaration(t)
		case *ast.BackendDeclaration:
			decl = f.formatBackendDeclaration(t)
		case *ast.DirectorDeclaration:
			decl = f.formatDirectorDeclaration(t)
		case *ast.TableDeclaration:
			decl = f.formatTableDeclaration(t)

		// penaltybox, ratecounter, and subroutine have trailing comment on the block statement
		case *ast.PenaltyboxDeclaration:
			decl = f.formatPenaltyboxDeclaration(t)
			trailingNode = t.Block
		case *ast.RatecounterDeclaration:
			decl = f.formatRatecounterDeclaration(t)
			trailingNode = t.Block
		case *ast.SubroutineDeclaration:
			decl = f.formatSubroutineDeclaration(t)
			trailingNode = t.Block
		default:
			return nil
		}

		var lf string
		if stmt.GetMeta().PreviousEmptyLines > 0 {
			lf = "\n"
		}

		decl.Buffer = fmt.Sprintf(
			"%s%s%s%s",
			f.formatComment(stmt.GetMeta().Leading, "\n", 0),
			lf,
			decl.Buffer,
			f.trailing(trailingNode.GetMeta().Trailing),
		)
		decls = append(decls, decl)
	}

	// If all declarations should be sorted, do it
	if f.conf.SortDeclaration {
		decls.Sort()
	}

	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	for i, decl := range decls {
		if i > 0 {
			buf.WriteString("\n")
			if decl.Type != Import && decl.Type != Include {
				buf.WriteString("\n")
			}
		}
		buf.WriteString(decl.Buffer)
	}
	buf.WriteString("\n")

	return bytes.NewReader(buf.Bytes())
}

// Calculate and crate ident strings from config (shorthand, without passing config)
func (f *Formatter) indent(level int) string {
	return indent(f.conf, level)
}

// Calculate trailing comments if exists
func (f *Formatter) trailing(trailing ast.Comments) string {
	var c string

	if len(trailing) == 0 {
		return c
	}
	c += strings.Repeat(" ", f.conf.TrailingCommentWidth)
	c += f.formatComment(trailing, "", 0)
	return c
}

// Format leading/infix/trailing comments
func (f *Formatter) formatComment(comments ast.Comments, sep string, level int) string {
	if len(comments) == 0 {
		return ""
	}

	buf := bufferPool.Get().(*bytes.Buffer) // nolint:errcheck
	defer bufferPool.Put(buf)

	buf.Reset()
	for i := range comments {
		if comments[i].PreviousEmptyLines > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString(f.indent(level))
		switch f.conf.CommentStyle {
		case config.CommentStyleSharp, config.CommentStyleSlash:
			r := '#' // default as sharp style comment
			if f.conf.CommentStyle == config.CommentStyleSlash {
				r = '/'
			}
			buf.WriteString(formatCommentCharacter(comments[i].String(), r))
		default:
			buf.WriteString(comments[i].String())
		}
		buf.WriteString(sep)
	}

	return buf.String()
}
