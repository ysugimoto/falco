package main

import (
	"bytes"
	_context "context"
	"fmt"
	"os"
	"strings"
	"time"

	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/plugin"
)

var (
	ErrParser   = fmt.Errorf("parser error")
	DotfileName = ".falcorc"
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
	overrides    map[string]linter.Severity
	lexers       map[string]*lexer.Lexer

	level Level

	// Note: this context is not Go context, our parsing context :)
	context *context.Context

	// runner result fields
	infos    int
	warnings int
	errors   int
}

func NewRunner(mainVcl string, c *Config) (*Runner, error) {
	r := &Runner{
		mainVclFile: mainVcl,
		context:     context.New(),
		level:       LevelError,
		overrides:   make(map[string]linter.Severity),
		lexers:      make(map[string]*lexer.Lexer),
	}

	if c.Remote {
		writeln(cyan, "Remote option supplied. Fetch snippets from Fastly.")
		// If remote flag is provided, fetch predefined data from Fastly.
		// Currently, we only support Edge Dictionary.
		//
		// We communicate Fastly API with service id and api key,
		// lookup fixed environment variable, FASTLY_SERVICE_ID and FASTLY_API_KEY
		// So user needs to set them with "-r" argument.
		serviceId := os.Getenv("FASTLY_SERVICE_ID")
		apiKey := os.Getenv("FASTLY_API_KEY")
		if serviceId == "" || apiKey == "" {
			return nil, errors.New("Both FASTLY_SERVICE_ID and FASTLY_API_KEY environment variables must be specified")
		}
		func() {
			ctx, timeout := _context.WithTimeout(_context.Background(), 20*time.Second)
			defer timeout()

			snippet := NewSnippet(serviceId, apiKey)
			// Remote communication is optional so we keep processing even if remote communication is failed
			if err := snippet.Fetch(ctx); err != nil {
				writeln(red, err.Error())
			} else if err := snippet.Compile(r.context); err != nil {
				writeln(red, err.Error())
			}
		}()
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

	// Make overriding error level setting from rc file
	r.initOverrides()

	return r, nil
}

func (r *Runner) initOverrides() {
	// find up rc file
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	var rcFile string
	for {
		rcFile = filepath.Join(cwd, DotfileName)
		if _, err := os.Stat(rcFile); err == nil {
			break
		}
		cwd = filepath.Dir(cwd)
		if cwd == "/" {
			// find up to root directory, stop it
			return
		}
	}

	fp, err := os.Open(rcFile)
	if err != nil {
		writeln(yellow, "Configuration file found at %s but could not open", rcFile)
		return
	}
	defer fp.Close()
	o := make(map[string]string)
	if err := yaml.NewDecoder(fp).Decode(&o); err != nil {
		writeln(yellow, "Failed to decode configuration file at %s: %s", rcFile, err)
		return
	}

	// validate configuration file
	for k, v := range o {
		switch strings.ToUpper(v) {
		case "ERROR":
			r.overrides[k] = linter.ERROR
		case "WARNING":
			r.overrides[k] = linter.WARNING
		case "INFO":
			r.overrides[k] = linter.INFO
		case "IGNORE":
			r.overrides[k] = linter.IGNORE
		default:
			writeln(yellow, "level for rule %s has invalid value %s, skip it.", k, v)
			return
		}
	}
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
	vcls, err := r.run(r.mainVclFile, true)
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

func (r *Runner) run(vclFile string, isMain bool) ([]*plugin.VCL, error) {
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
		return nil, ErrParser
	}
	lx.NewLine()
	r.lexers[vclFile] = lx

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

		subVcl, err := r.run(file, false)
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
	lt.Lint(vcl, r.context, isMain)
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
		lx = r.lexers[err.Token.File]
	}

	// check severity with overrides
	severity := err.Severity
	if v, ok := r.overrides[string(err.Rule)]; ok {
		severity = v
	}

	switch severity {
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
	case linter.IGNORE:
		return
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
