package main

import (
	"fmt"
	"os"
	"strings"

	"path/filepath"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/remote"
)

type Resolver struct {
	includePaths []string
	snippets     []*remote.VCLSnippet
}

func newResolver() *Resolver {
	return &Resolver{}
}

func (r *Resolver) addIncludePaths(ps ...string) {
	r.includePaths = append(r.includePaths, ps...)
}

func (r *Resolver) addSnippets(snip ...*remote.VCLSnippet) {
	r.snippets = append(r.snippets, snip...)
}

func (r *Resolver) FormatError(m *ast.Meta, err error) error {
	// Bad logic, but temporary OK :(
	if strings.Contains(err.Error(), "Caused at") {
		return err
	}

	return fmt.Errorf(
		"%s\nCaused at %s, line: %d, position: %d",
		err, m.Token.File, m.Token.Line, m.Token.Position,
	)
}

func (r *Resolver) Resolve(s []ast.Statement, phase remote.SnippetType) ([]ast.Statement, error) {
	var resolved []ast.Statement

	for i := range s {
		switch t := s[i].(type) {
		// Following statement/declaration could have "include" statement in sub block
		case *ast.IncludeStatement:
			var founds []ast.Statement
			var err error

			// If module name starts with "snippet::", find from VCL snippets managed in Fastly.
			if strings.HasPrefix(t.Module.Value, "snippet::") {
				founds, err = r.findSnippets(strings.TrimPrefix(t.Module.Value, "snippet::"), phase)
			} else {
				founds, err = r.findFile(t.Module.Value, phase)
			}
			if err != nil {
				return nil, r.FormatError(t.GetMeta(), err)
			}
			resolved = append(resolved, founds...)
		case *ast.IfStatement:
			if err := r.resolveIfStatement(t, phase); err != nil {
				return nil, r.FormatError(t.GetMeta(), err)
			}
			resolved = append(resolved, t)
		case *ast.SubroutineDeclaration:
			if err := r.resolveSubroutine(t); err != nil {
				return nil, r.FormatError(t.GetMeta(), err)
			}
			resolved = append(resolved, t)
		default:
			resolved = append(resolved, t)
		}
	}

	return resolved, nil
}

func (r *Resolver) findSnippets(modName string, phase remote.SnippetType) ([]ast.Statement, error) {
	var statements []ast.Statement

	for _, snip := range r.snippets {
		if snip.Name != modName {
			continue
		}

		ss, err := r.parseStatements(
			parser.New(lexer.NewFromString(*snip.Content, lexer.WithFile("snippet::"+modName))),
			phase,
		)
		if err != nil {
			return nil, err
		}
		statements = append(statements, ss...)
	}

	return statements, nil
}

func (r *Resolver) findSnippetsByPhase(phase remote.SnippetType) ([]ast.Statement, error) {
	var statements []ast.Statement

	for _, snip := range r.snippets {
		if snip.Type != phase {
			continue
		}

		ss, err := r.parseStatements(
			parser.New(lexer.NewFromString(*snip.Content, lexer.WithFile("snippet::"+snip.Name))),
			phase,
		)
		if err != nil {
			return nil, err
		}
		statements = append(statements, ss...)
	}

	return statements, nil
}

func (r *Resolver) findFile(modName string, phase remote.SnippetType) ([]ast.Statement, error) {
	var file string

	// Find for each include paths
	for _, ip := range r.includePaths {
		if _, err := os.Stat(filepath.Join(ip, modName+".vcl")); err == nil {
			file = filepath.Join(ip, modName+".vcl")
			break
		}
	}

	if file == "" {
		return nil, fmt.Errorf("Could not find module file: %s.vcl in include paths", modName)
	}

	fp, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to open file: %s.vcl: %w", modName, err)
	}
	defer fp.Close()

	return r.parseStatements(parser.New(lexer.New(fp, lexer.WithFile(file))), phase)
}

func (r *Resolver) parseStatements(p *parser.Parser, phase remote.SnippetType) ([]ast.Statement, error) {
	var ss []ast.Statement
	var err error

	if phase == remote.SnippetTypeInit {
		if vcl, err := p.ParseVCL(); err != nil {
			return nil, err
		} else {
			ss = vcl.Statements
		}
	} else {
		ss, err = p.ParseStatement()
		if err != nil {
			return nil, err
		}
	}

	ss, err = r.Resolve(ss, phase)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (r *Resolver) resolveIfStatement(stmt *ast.IfStatement, phase remote.SnippetType) error {
	var err error

	// Resolve consequence
	stmt.Consequence.Statements, err = r.Resolve(stmt.Consequence.Statements, phase)
	if err != nil {
		return err
	}

	// Resolve another (else if)
	for i, alt := range stmt.Another {
		alt.Consequence.Statements, err = r.Resolve(alt.Consequence.Statements, phase)
		if err != nil {
			return err
		}
		stmt.Another[i] = alt
	}

	// Resolve alternative
	if stmt.Alternative != nil {
		stmt.Alternative.Statements, err = r.Resolve(stmt.Alternative.Statements, phase)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Resolver) resolveSubroutine(decl *ast.SubroutineDeclaration) error {
	var err error

	scope := getFastlySubroutineScope(decl.Name.Value)
	if scope != "" {
		// pp.Println(decl.Block.InfixComment())
		// if "FASTLY [phase]" macro found in subroutine root, prepend snippet
		if hasFastlyBoilerPlateMacro(decl.Block.InfixComment(), "FASTLY "+scope) {
			ss, err := r.findSnippetsByPhase(remote.SnippetType(scope))
			if err != nil {
				return nil
			}
			decl.Block.Statements = append(ss, decl.Block.Statements...)
		}

		var statements []ast.Statement
		// Macro found in some statements, prepend before its statement
		for _, stmt := range decl.Block.Statements {
			if !hasFastlyBoilerPlateMacro(stmt.LeadingComment(), "FASTLY "+scope) {
				statements = append(statements, stmt)
				continue
			}
			ss, err := r.findSnippetsByPhase(remote.SnippetType(scope))
			if err != nil {
				return nil
			}
			statements = append(statements, ss...)
			statements = append(statements, stmt)
		}
		decl.Block.Statements = statements
	}

	// Resolve subroutine inside statements
	decl.Block.Statements, err = r.Resolve(decl.Block.Statements, remote.SnippetType(scope))
	if err != nil {
		return err
	}
	return nil
}

// TODO: duplicate with linter:getFastlySubroutineScope, should integrate as utility (@ysugimoto)
func getFastlySubroutineScope(name string) string {
	switch name {
	case "vcl_recv":
		return "recv"
	case "vcl_hash":
		return "hash"
	case "vcl_hit":
		return "hit"
	case "vcl_miss":
		return "miss"
	case "vcl_pass":
		return "pass"
	case "vcl_fetch":
		return "fetch"
	case "vcl_error":
		return "error"
	case "vcl_deliver":
		return "deliver"
	case "vcl_log":
		return "log"
	}
	return ""
}

// TODO: duplicate with linter:hasFastlyBoilerPlateMacro, should integrate as utility (@ysugimoto)
func hasFastlyBoilerPlateMacro(commentText, phrase string) bool {
	comments := strings.Split(commentText, "\n")
	for _, c := range comments {
		c = strings.TrimLeft(c, " */#")
		if strings.HasPrefix(strings.ToUpper(c), strings.ToUpper(phrase)) {
			return true
		}
	}
	return false
}
