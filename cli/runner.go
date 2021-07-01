package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/plugin"
)

var (
	ErrParser = fmt.Errorf("parser error")
)

type Level int

const (
	LevelError Level = iota
	LevelWarning
	LevelInfo
)

type RunnerResult struct {
	Infos    int
	Warnings int
	Errors   int
	Vcls     []*plugin.VCL
}

type Runner struct {
	transformers []*Transformer
	includePaths []string
	mainVclFile  string

	level Level

	// Note: this context is not Go context, our parsing context :)
	context *context.Context

	// runner result fields
	infos    int
	warnings int
	errors   int
}

func NewRunner(mainVcl string, c *Config) (*Runner, error) {
	// Validate main VCL
	if mainVcl == "" {
		return nil, fmt.Errorf("Main VCL file is not specified.")
	} else if _, err := os.Stat(mainVcl); err != nil {
		if err == os.ErrNotExist {
			return nil, fmt.Errorf("%s is not found", mainVcl)
		}
		return nil, fmt.Errorf("Unexpected stat error: %s", err.Error())
	}

	mainVcl, _ = filepath.Abs(mainVcl) // nolint: errcheck
	r := &Runner{
		mainVclFile: mainVcl,
		context:     context.New(),
		level:       LevelError,
	}

	// Directory which placed main VCL adds to include path
	r.includePaths = append(r.includePaths, filepath.Dir(mainVcl))

	// Add include paths as absolute
	for i := range c.IncludePaths {
		abs, err := filepath.Abs(c.IncludePaths[i])
		if err == nil {
			r.includePaths = append(r.includePaths, abs)
		}
	}

	// Check transformer exists and format to absolute path
	// Transformer is provided as independent binary, named "falco-transform-[name]"
	// so, if transformer specified with "lambdaedge", program lookup "falco-transform-lambdaedge" binary existence
	for i := range c.Transforms {
		tf, err := NewTransformer(c.Transforms[i])
		if err != nil {
			return nil, err
		}
		r.transformers = append(r.transformers, tf)
	}

	// Set verbose level
	if c.VV {
		r.level = LevelInfo
	} else if c.V {
		r.level = LevelWarning
	}

	return r, nil
}

func (r *Runner) Transform(vcls []*plugin.VCL) error {
	// VCL data is shared between parser and transformar through the falco/io package.
	encoded, err := plugin.Encode(vcls)
	if err != nil {
		return fmt.Errorf("Failed to encode VCL: %w", err)
	}

	for _, t := range r.transformers {
		if err := t.Execute(bytes.NewReader(encoded)); err != nil {
			return fmt.Errorf("Failed to execute %s transformer: %w", t.command, err)
		}
	}
	return nil
}

func (r *Runner) Run() (*RunnerResult, error) {
	vcls, err := r.run(r.mainVclFile)
	if err != nil {
		return nil, err
	}

	return &RunnerResult{
		Infos:    r.infos,
		Warnings: r.warnings,
		Errors:   r.errors,
		Vcls:     vcls,
	}, nil
}

func (r *Runner) run(vclFile string) ([]*plugin.VCL, error) {
	fp, err := os.Open(vclFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to open file: %s", vclFile)
	}
	defer fp.Close()

	lx := lexer.New(fp, lexer.WithFile(vclFile))
	p := parser.New(lx)
	vcl, err := p.ParseVCL()
	if err != nil {
		lx.NewLine()
		pe, ok := errors.Cause(err).(*parser.ParseError)
		if ok {
			r.printParseError(lx, pe)
		}
		fmt.Printf("%+v\n", err)
		return nil, ErrParser
	}
	lx.NewLine()

	var vcls []*plugin.VCL
	// Lint dependent VCLs before execute main VCL
	for _, stmt := range vcl.Statements {
		include, ok := stmt.(*ast.IncludeStatement)
		if !ok {
			continue
		}

		var file string
		// Find for each include paths
		for _, p := range r.includePaths {
			if _, err := os.Stat(filepath.Join(p, include.Module.Value+".vcl")); err == nil {
				file = filepath.Join(p, include.Module.Value+".vcl")
				break
			}
		}

		subVcl, err := r.run(file)
		if err != nil {
			return nil, err
		}
		vcls = append(vcls, subVcl...)
	}

	// Append main to the last of proceeds VCLs
	vcls = append(vcls, &plugin.VCL{
		File: vclFile,
		AST:  vcl,
	})

	lt := linter.New()
	lt.Lint(vcl, r.context)
	if len(lt.Errors) > 0 {
		for _, err := range lt.Errors {
			le, ok := err.(*linter.LintError)
			if !ok {
				continue
			}
			r.printLinterError(lx, le)
		}
	}

	return vcls, nil
}

func (r *Runner) printParseError(lx *lexer.Lexer, err *parser.ParseError) {
	var file string
	if err.Token.File != "" {
		file = "in " + err.Token.File + " "
	}
	writeln(red, ":boom: %s\n%sat line %d, position %d", err.Message, file, err.Token.Line, err.Token.Position)

	problemLine := err.Token.Line
	for l := problemLine - 5; l <= problemLine; l++ {
		line, ok := lx.GetLine(l)
		if !ok {
			continue
		}
		tabCount := strings.Count(line, "\t")
		if l == problemLine {
			writeln(yellow, " %d|%s", l, strings.ReplaceAll(line, "\t", "    "))
			lineLength := len(fmt.Sprint(l))
			prefixSpaceSize := lineLength + err.Token.Position - tabCount + (tabCount * 4)
			writeln(white, " %s%s",
				strings.Repeat(" ", prefixSpaceSize),
				strings.Repeat("^", len([]rune(err.Token.Literal))+err.Token.Offset),
			)
		} else {
			writeln(white, " %d|%s", l, strings.ReplaceAll(line, "\t", "    "))
		}
	}
}

func (r *Runner) printLinterError(lx *lexer.Lexer, err *linter.LintError) {
	var rule, file string

	if err.Rule != "" {
		rule = " (" + string(err.Rule) + ")"
	}
	if err.Token.File != "" {
		file = "in " + err.Token.File + " "
	}

	switch err.Severity {
	case linter.ERROR:
		r.errors++
		writeln(red, ":fire:[ERROR] %s%s", err.Message, rule)
	case linter.WARNING:
		r.warnings++
		if r.level < LevelWarning {
			return
		}
		writeln(yellow, ":exclamation:[WARNING] %s%s", err.Message, rule)
	case linter.INFO:
		r.infos++
		if r.level < LevelInfo {
			return
		}
		writeln(cyan, ":speaker:[INFO] %s%s", err.Message, rule)
	}

	writeln(white, "%sat line %d, position %d", file, err.Token.Line, err.Token.Position)

	problemLine := err.Token.Line
	for l := problemLine - 1; l <= problemLine+1; l++ {
		line, ok := lx.GetLine(l)
		if !ok {
			continue
		}
		tabCount := strings.Count(line, "\t")
		if l == problemLine {
			writeln(yellow, " %d|%s", l, strings.ReplaceAll(line, "\t", "    "))
			lineLength := len(fmt.Sprint(l))
			prefixSpaceSize := lineLength + err.Token.Position - tabCount + (tabCount * 4)
			writeln(white, " %s%s",
				strings.Repeat(" ", prefixSpaceSize),
				strings.Repeat("^", len([]rune(err.Token.Literal))+err.Token.Offset),
			)
		} else {
			writeln(white, " %d|%s", l, strings.ReplaceAll(line, "\t", "    "))
		}
	}

	if err.Reference != "" {
		writeln(white, "See document in detail: %s", err.Reference)
	}
	writeln(white, "")
}
