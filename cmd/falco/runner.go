package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/debugger"
	"github.com/ysugimoto/falco/formatter"
	"github.com/ysugimoto/falco/interpreter"
	icontext "github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/plugin"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/snippets"
	"github.com/ysugimoto/falco/tester"
	"github.com/ysugimoto/falco/types"
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

	LintErrors  map[string][]*linter.LintError
	ParseErrors map[string]*parser.ParseError

	Vcl *plugin.VCL
}

type StatsResult struct {
	Main        string `json:"main"`
	Subroutines int    `json:"subroutines"`
	Tables      int    `json:"tables"`
	Backends    int    `json:"backends"`
	Acls        int    `json:"acls"`
	Directors   int    `json:"directors"`
	Files       int    `json:"files"`
	Lines       int    `json:"lines"`
}

type Fetcher interface {
	Backends() ([]*types.RemoteBackend, error)
	Dictionaries() ([]*types.RemoteDictionary, error)
	Acls() ([]*types.RemoteAcl, error)
	Snippets() ([]*types.RemoteVCL, error)
}

type RunMode int

const (
	RunModeLint RunMode = 0x000001
	RunModeStat RunMode = 0x000010
)

type Runner struct {
	transformers []*Transformer
	overrides    map[string]linter.Severity
	lexers       map[string]*lexer.Lexer
	snippets     *snippets.Snippets
	config       *config.Config

	level       Level
	lintErrors  map[string][]*linter.LintError
	parseErrors map[string]*parser.ParseError

	// runner result fields
	infos    int
	warnings int
	errors   int
}

// Wrap writeln function in order to prevent to write when json mode turns on
func (r *Runner) message(c *color.Color, format string, args ...interface{}) {
	// Suppress output when JSON mode turns on
	// This is because JSON only should display JSON string
	// so any other messages we must not output
	if r.config.Json {
		return
	}
	write(c, format, args...)
}

func NewRunner(c *config.Config, fetcher snippets.Fetcher) (*Runner, error) {
	r := &Runner{
		level:       LevelError,
		overrides:   make(map[string]linter.Severity),
		lexers:      make(map[string]*lexer.Lexer),
		config:      c,
		lintErrors:  make(map[string][]*linter.LintError),
		parseErrors: make(map[string]*parser.ParseError),
	}

	// If fetch interface is provided, communicate with it
	if fetcher != nil {
		s, err := snippets.Fetch(fetcher)
		if err != nil {
			r.message(red, err.Error()+"\n")
		}
		r.snippets = s
		if err := r.snippets.FetchLoggingEndpoint(fetcher); err != nil {
			r.message(red, err.Error()+"\n")
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
	if c.Linter.VerboseInfo {
		r.level = LevelInfo
	} else if c.Linter.VerboseWarning {
		r.level = LevelWarning
	}

	// Override linter rules
	for key, value := range c.Linter.Rules {
		switch strings.ToUpper(value) {
		case "ERROR":
			r.overrides[key] = linter.ERROR
		case "WARNING":
			r.overrides[key] = linter.WARNING
		case "INFO":
			r.overrides[key] = linter.INFO
		case "IGNORE":
			r.overrides[key] = linter.IGNORE
		default:
			r.message(yellow, "Level for rule %s has invalid value %s, skipping.\n", key, value)
		}
	}

	return r, nil
}

func (r *Runner) Transform(vcl *plugin.VCL) error {
	// VCL data is shared between parser and transformar through the falco/io package.
	encoded, err := plugin.Encode(vcl)
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

func (r *Runner) Run(rslv resolver.Resolver) (*RunnerResult, error) {
	options := []context.Option{context.WithResolver(rslv)}
	// If remote snippets exists, prepare parse and prepend to main VCL
	if r.snippets != nil {
		options = append(options, context.WithSnippets(r.snippets))
	}

	main, err := rslv.MainVCL()
	if err != nil {
		return nil, err
	}

	// Note: this context is not Go context, our parsing context :)
	ctx := context.New(options...)
	vcl, err := r.run(ctx, main, RunModeLint)
	if err != nil && !r.config.Json {
		return nil, err
	}

	return &RunnerResult{
		Infos:       r.infos,
		Warnings:    r.warnings,
		Errors:      r.errors,
		LintErrors:  r.lintErrors,
		ParseErrors: r.parseErrors,
		Vcl:         vcl,
	}, nil
}

func (r *Runner) run(ctx *context.Context, main *resolver.VCL, mode RunMode) (*plugin.VCL, error) {
	vcl, err := r.parseVCL(main.Name, main.Data)
	if err != nil {
		return nil, err
	}

	// If remote snippets exists, prepare parse and prepend to main VCL
	if r.snippets != nil {
		for _, snip := range r.snippets.EmbedSnippets() {
			s, err := r.parseVCL(snip.Name, snip.Data)
			if err != nil {
				return nil, err
			}
			vcl.Statements = append(s.Statements, vcl.Statements...)
		}
	}

	lt := linter.New(r.config.Linter)
	lt.Lint(vcl, ctx)

	for k, v := range lt.Lexers() {
		r.lexers[k] = v
	}

	// If runner is running as stat mode, prevent to output lint result
	if mode&RunModeStat > 0 {
		return nil, nil
	}

	// Checking Fatal error, it means parse error occurs on included submodule
	if lt.FatalError != nil {
		if pe, ok := lt.FatalError.Error.(*parser.ParseError); ok {
			var file string
			if pe.Token.File != "" {
				file = "in " + pe.Token.File + " "
			}
			// Nothing to print to stdout if JSON mode is enabled, exit early.
			if r.config.Json {
				r.parseErrors[pe.Token.File] = pe
			} else {
				r.printParseError(lt.FatalError.Lexer, file, pe)
			}
		}
		return nil, ErrParser
	}

	if len(lt.Errors) > 0 {
		for _, err := range lt.Errors {
			le, ok := err.(*linter.LintError)
			if !ok {
				continue
			}
			// check severity with overrides
			severity := le.Severity
			if v, ok := r.overrides[string(le.Rule)]; ok {
				severity = v
			}

			// Store all but ignored linter errors
			if r.config.Json && severity != linter.IGNORE {
				r.lintErrors[le.Token.File] = append(r.lintErrors[le.Token.File], le)
			}
			r.printLinterError(r.lexers[main.Name], severity, le)
		}
	}

	return &plugin.VCL{
		File: main.Name,
		AST:  vcl,
	}, nil
}

func (r *Runner) parseVCL(name, code string) (*ast.VCL, error) {
	lx := lexer.NewFromString(code, lexer.WithFile(name))
	p := parser.New(lx)
	vcl, err := p.ParseVCL()
	if err != nil {
		lx.NewLine()
		pe, ok := errors.Cause(err).(*parser.ParseError)
		if ok {
			var file string
			if pe.Token.File != "" {
				file = "in " + pe.Token.File + " "
			}
			// Nothing to print to stdout if JSON mode is enabled, exit early.
			if r.config.Json {
				r.parseErrors[pe.Token.File] = pe
			}
			r.printParseError(lx, file, pe)
		}
		return nil, ErrParser
	}

	lx.NewLine()
	r.lexers[name] = lx
	return vcl, nil
}

func (r *Runner) printParseError(lx *lexer.Lexer, file string, err *parser.ParseError) {
	r.message(red, ":boom: %s\n%sat line %d, position %d\n", err.Message, file, err.Token.Line, err.Token.Position)

	problemLine := err.Token.Line
	for l := problemLine - 5; l <= problemLine; l++ {
		line, ok := lx.GetLine(l)
		if !ok {
			continue
		}
		tabCount := strings.Count(line, "\t")
		if l == problemLine {
			r.message(yellow, " %d|%s\n", l, strings.ReplaceAll(line, "\t", "    "))
			lineLength := len(fmt.Sprint(l))
			prefixSpaceSize := lineLength + err.Token.Position - tabCount + (tabCount * 4)
			r.message(white, " %s%s\n",
				strings.Repeat(" ", prefixSpaceSize),
				strings.Repeat("^", len([]rune(err.Token.Literal))+err.Token.Offset),
			)
		} else {
			r.message(white, " %d|%s\n", l, strings.ReplaceAll(line, "\t", "    "))
		}
	}
}

func (r *Runner) printLinterError(lx *lexer.Lexer, severity linter.Severity, err *linter.LintError) {
	var rule, file string

	if err.Rule != "" {
		rule = " (" + string(err.Rule) + ")"
	}

	// Override lexer because error may cause in other included module
	if err.Token.File != "" {
		file = "in " + err.Token.File + " "
		lx = r.lexers[err.Token.File]
	}

	switch severity {
	case linter.ERROR:
		r.errors++
		r.message(red, ":fire:[ERROR] %s%s\n", err.Message, rule)
	case linter.WARNING:
		r.warnings++
		if r.level < LevelWarning {
			return
		}
		r.message(yellow, ":exclamation:[WARNING] %s%s\n", err.Message, rule)
	case linter.INFO:
		r.infos++
		if r.level < LevelInfo {
			return
		}
		r.message(cyan, ":speaker:[INFO] %s%s\n", err.Message, rule)
	case linter.IGNORE:
		return
	}

	r.message(white, "%sat line %d, position %d\n", file, err.Token.Line, err.Token.Position)

	problemLine := err.Token.Line
	for l := problemLine - 1; l <= problemLine+1; l++ {
		line, ok := lx.GetLine(l)
		if !ok {
			continue
		}
		tabCount := strings.Count(line, "\t")
		if l == problemLine {
			r.message(yellow, " %d|%s\n", l, strings.ReplaceAll(line, "\t", "    "))
			lineLength := len(fmt.Sprint(l))
			prefixSpaceSize := lineLength + err.Token.Position - tabCount + (tabCount * 4)
			r.message(white, " %s%s\n",
				strings.Repeat(" ", prefixSpaceSize),
				strings.Repeat("^", len([]rune(err.Token.Literal))+err.Token.Offset),
			)
		} else {
			r.message(white, " %d|%s\n", l, strings.ReplaceAll(line, "\t", "    "))
		}
	}

	if err.Reference != "" {
		r.message(white, "See reference documentation: %s\n", err.Reference)
	}
	r.message(white, "\n")
}

func (r *Runner) Stats(rslv resolver.Resolver) (*StatsResult, error) {
	options := []context.Option{context.WithResolver(rslv)}
	// If remote snippets exists, prepare parse and prepend to main VCL
	if r.snippets != nil {
		options = append(options, context.WithSnippets(r.snippets))
	}

	main, err := rslv.MainVCL()
	if err != nil {
		return nil, err
	}

	// Note: this context is not Go context, our parsing context :)
	ctx := context.New(options...)

	if _, err := r.run(ctx, main, RunModeStat); err != nil {
		return nil, err
	}

	stats := &StatsResult{
		Main:        main.Name,
		Subroutines: len(ctx.Subroutines),
		Tables:      len(ctx.Tables),
		Backends:    len(ctx.Backends),
		Acls:        len(ctx.Acls),
		Directors:   len(ctx.Directors),
	}

	for _, lx := range r.lexers {
		stats.Files++
		stats.Lines += lx.LineCount()
	}

	return stats, nil
}

func (r *Runner) Simulate(rslv resolver.Resolver) error {
	sc := r.config.Simulator
	options := []icontext.Option{
		icontext.WithResolver(rslv),
		icontext.WithMaxBackends(r.config.OverrideMaxBackends),
		icontext.WithMaxAcls(r.config.OverrideMaxAcls),
	}
	if r.snippets != nil {
		options = append(options, icontext.WithSnippets(r.snippets))
	}
	if sc.OverrideRequest != nil {
		options = append(options, icontext.WithRequest(sc.OverrideRequest))
	}
	if r.config.OverrideBackends != nil {
		options = append(options, icontext.WithOverrideBackends(r.config.OverrideBackends))
	}

	i := interpreter.New(options...)

	if sc.IsDebug {
		// If debugger flag is on, run debugger mode
		return debugger.New(i).Run(sc)
	}

	// Otherwise, simply start simulator server
	mux := http.NewServeMux()
	mux.Handle("/", i)
	s := &http.Server{
		Handler: mux,
		Addr:    fmt.Sprintf(":%d", sc.Port),
	}

	if sc.KeyFile != "" && sc.CertFile != "" {
		writeln(green, "Simulator server starts on 0.0.0.0:%d with TLS", sc.Port)
		return s.ListenAndServeTLS(sc.CertFile, sc.KeyFile)
	}
	writeln(green, "Simulator server starts on 0.0.0.0:%d", sc.Port)
	return s.ListenAndServe()
}

func (r *Runner) Test(rslv resolver.Resolver) (*tester.TestFactory, error) {
	tc := r.config.Testing
	options := []icontext.Option{
		icontext.WithResolver(rslv),
		icontext.WithMaxBackends(r.config.OverrideMaxBackends),
		icontext.WithMaxAcls(r.config.OverrideMaxAcls),
	}
	if r.snippets != nil {
		options = append(options, icontext.WithSnippets(r.snippets))
	}
	if tc.OverrideRequest != nil {
		options = append(options, icontext.WithRequest(tc.OverrideRequest))
	}
	if tc.OverrideHost != "" {
		options = append(options, icontext.WithOverrideHost(tc.OverrideHost))
	}

	r.message(white, "Running tests...")
	factory, err := tester.New(tc, options).Run(r.config.Commands.At(1))
	if err != nil {
		writeln(red, " Failed.")
		writeln(red, "Failed to run test: %s", err.Error())
		return nil, err
	}
	r.message(white, " Done.\n")
	return factory, nil
}

func (r *Runner) Format(rslv resolver.Resolver) error {
	main, err := rslv.MainVCL()
	if err != nil {
		return err
	}
	vcl, err := r.parseVCL(main.Name, main.Data)
	if err != nil {
		return err
	}

	formatted := formatter.New(r.config.Format).Format(vcl)
	var w io.Writer
	if r.config.Format.Overwrite {
		writeln(cyan, "Formatted %s.", main.Name)
		fp, err := os.OpenFile(main.Name, os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return errors.WithStack(err)
		}
		defer fp.Close()
		w = fp
	} else {
		w = os.Stdout
	}
	if _, err := io.Copy(w, formatted); err != nil {
		return err
	}
	return nil
}
