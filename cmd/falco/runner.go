package main

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/plugin"
	"github.com/ysugimoto/falco/remote"
	"github.com/ysugimoto/falco/resolver"
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
	snippets     *context.FastlySnippet

	level       Level
	lintErrors  map[string][]*linter.LintError
	parseErrors map[string]*parser.ParseError

	// runner result fields
	infos    int
	warnings int
	errors   int

	jsonMode bool
}

func NewRunner(c *config.Config, f Fetcher) (*Runner, error) {
	r := &Runner{
		level:     LevelError,
		overrides: make(map[string]linter.Severity),
		lexers:    make(map[string]*lexer.Lexer),
	}

	if c.Json {
		r.jsonMode = true
		r.lintErrors = make(map[string][]*linter.LintError)
		r.parseErrors = make(map[string]*parser.ParseError)
	}

	if c.Remote {
		if !r.jsonMode {
			writeln(cyan, "Remote option supplied. Fetch snippets from Fastly.")
		}
		// If remote flag is provided, fetch predefined data from Fastly.
		// Currently, we only support Edge Dictionary.
		//
		// We communicate Fastly API with service id and api key,
		// lookup fixed environment variable, FASTLY_SERVICE_ID and FASTLY_API_KEY
		// So user needs to set them with "-r" argument.
		if c.FastlyServiceID == "" || c.FastlyApiKey == "" {
			return nil, errors.New("Both FASTLY_SERVICE_ID and FASTLY_API_KEY environment variables must be specified")
		}
		func() {
			// Remote communication is optional so we keep processing even if remote communication is failed
			// We allow each API call to take up to to 5 seconds
			f := remote.NewFastlyApiFetcher(c.FastlyServiceID, c.FastlyApiKey, 5*time.Second)
			snippets, err := NewSnippet(f).Fetch()
			if err != nil && !r.jsonMode {
				writeln(red, err.Error())
			}
			// Stack to runner field, combime before run()
			r.snippets = snippets
		}()
	}

	if f != nil {
		snippets, err := NewSnippet(f).Fetch()
		if err != nil && !r.jsonMode {
			writeln(red, err.Error())
		}
		r.snippets = snippets
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
	if c.VerboseInfo {
		r.level = LevelInfo
	} else if c.VerboseWarning {
		r.level = LevelWarning
	}

	// Override linter rules
	for key, value := range c.Rules {
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
			if !r.jsonMode {
				writeln(yellow, "level for rule %s has invalid value %s, skip it.", key, value)
			}
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
		options = append(options, context.WithFastlySnippets(r.snippets))
	}

	main, err := rslv.MainVCL()
	if err != nil {
		return nil, err
	}

	// Note: this context is not Go context, our parsing context :)
	ctx := context.New(options...)
	vcl, err := r.run(ctx, main, RunModeLint)
	if err != nil {
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

	lt := linter.New()
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
			r.printParseError(lt.FatalError.Lexer, pe)
		}
		return nil, ErrParser
	}

	if len(lt.Errors) > 0 {
		for _, err := range lt.Errors {
			le, ok := err.(*linter.LintError)
			if !ok {
				continue
			}
			r.printLinterError(r.lexers[main.Name], le)
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
			r.printParseError(lx, pe)
		}
		return nil, ErrParser
	}
	lx.NewLine()
	r.lexers[name] = lx
	return vcl, nil
}

func (r *Runner) printParseError(lx *lexer.Lexer, err *parser.ParseError) {
	var file string
	if err.Token.File != "" {
		file = "in " + err.Token.File + " "
		r.parseErrors[err.Token.File] = err
	}

	// Nothing to print to stdout if JSON mode is enabled, exit early.
	if r.jsonMode {
		return
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

	// Override lexer because error may cause in other included module
	if err.Token.File != "" {
		file = "in " + err.Token.File + " "
		lx = r.lexers[err.Token.File]
	}

	// check severity with overrides
	severity := err.Severity
	if v, ok := r.overrides[string(err.Rule)]; ok {
		severity = v
	}

	// Store all but ignored linter errors
	if severity != linter.IGNORE {
		r.lintErrors[err.Token.File] = append(r.lintErrors[err.Token.File], err)
	}

	switch severity {
	case linter.ERROR:
		r.errors++
		if r.jsonMode {
			return
		}
		writeln(red, ":fire:[ERROR] %s%s", err.Message, rule)
	case linter.WARNING:
		r.warnings++
		if r.jsonMode || r.level < LevelWarning {
			return
		}
		writeln(yellow, ":exclamation:[WARNING] %s%s", err.Message, rule)
	case linter.INFO:
		r.infos++
		if r.jsonMode || r.level < LevelInfo {
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

func (r *Runner) Stats(rslv resolver.Resolver) (*StatsResult, error) {
	options := []context.Option{context.WithResolver(rslv)}
	// If remote snippets exists, prepare parse and prepend to main VCL
	if r.snippets != nil {
		options = append(options, context.WithFastlySnippets(r.snippets))
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
