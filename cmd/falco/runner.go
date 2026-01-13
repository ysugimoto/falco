package main

import (
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/debugger"
	"github.com/ysugimoto/falco/formatter"
	"github.com/ysugimoto/falco/interpreter"
	icontext "github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter"
	lcontext "github.com/ysugimoto/falco/linter/context"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/snippet"
	"github.com/ysugimoto/falco/tester"
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

type VCL struct {
	File string
	AST  *ast.VCL
}

type RunnerResult struct {
	Infos    int
	Warnings int
	Errors   int

	LintErrors  map[string][]*linter.LintError
	ParseErrors map[string]*parser.ParseError

	Vcl *VCL
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

type RunMode int

const (
	RunModeLint RunMode = 0x000001
	RunModeStat RunMode = 0x000010
)

type Runner struct {
	overrides map[string]linter.Severity
	lexers    map[string]*lexer.Lexer
	snippets  *snippet.Snippets
	config    *config.Config

	level       Level
	lintErrors  map[string][]*linter.LintError
	parseErrors map[string]*parser.ParseError

	// runner result fields
	infos    int
	warnings int
	errors   int
}

// Wrap writeln function in order to prevent to write when json mode turns on
func (r *Runner) message(c *color.Color, format string, args ...any) {
	// Suppress output when JSON mode turns on
	// This is because JSON only should display JSON string
	// so any other messages we must not output
	if r.config.Json {
		return
	}
	write(c, format, args...)
}

func NewRunner(c *config.Config, fetcher snippet.Fetcher) *Runner {
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
		var snippets *snippet.Snippets
		var err error

		// Lookup snippets cache
		cache := fetcher.LookupCache(c.Refresh)
		if cache != nil {
			snippets = cache
			r.message(white, "Use cached remote snippets.\n")
		} else {
			snippets, err = snippet.Fetch(fetcher)
		}
		if err != nil {
			r.message(red, "%s\n", err.Error())
		}
		r.snippets = snippets
		if err := r.snippets.FetchLoggingEndpoint(fetcher); err != nil {
			r.message(red, "%s\n", err.Error())
		}
		// ...and save cache after the constructor
		defer fetcher.WriteCache(snippets)
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

	return r
}

func (r *Runner) Run(rslv resolver.Resolver) (*RunnerResult, error) {
	options := []lcontext.Option{lcontext.WithResolver(rslv)}
	// If remote snippets exists, prepare parse and prepend to main VCL
	if r.snippets != nil {
		options = append(options, lcontext.WithSnippets(r.snippets))
	}

	main, err := rslv.MainVCL()
	if err != nil {
		return nil, err
	}

	// Note: this context is not Go context, our linter context :)
	ctx := lcontext.New(options...)
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

func (r *Runner) run(ctx *lcontext.Context, main *resolver.VCL, mode RunMode) (*VCL, error) {
	vcl, err := r.parseVCL(main.Name, main.Data)
	if err != nil {
		return nil, err
	}

	// If remote snippets exists, prepare parse and prepend to main VCL
	if r.snippets != nil {
		snippets, err := r.snippets.EmbedSnippets(false) // disable TLS on linting
		if err != nil {
			return nil, errors.WithStack(err)
		}
		for _, snip := range snippets {
			s, err := r.parseVCL(snip.Name, snip.Data)
			if err != nil {
				return nil, err
			}
			vcl.Statements = append(s.Statements, vcl.Statements...)
		}
	}

	lt := linter.New(r.config.Linter)
	lt.Lint(vcl, ctx)

	maps.Copy(r.lexers, lt.Lexers())

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
		for _, le := range lt.Errors {
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

	return &VCL{
		File: main.Name,
		AST:  vcl,
	}, nil
}

func (r *Runner) parseVCL(name, code string) (*ast.VCL, error) {
	lx := lexer.NewFromString(code, lexer.WithFile(name))
	p := parser.New(lx)
	vcl, err := p.ParseVCLOrSnippet()
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
	options := []lcontext.Option{lcontext.WithResolver(rslv)}
	// If remote snippets exists, prepare parse and prepend to main VCL
	if r.snippets != nil {
		options = append(options, lcontext.WithSnippets(r.snippets))
	}

	main, err := rslv.MainVCL()
	if err != nil {
		return nil, err
	}

	// Note: this context is not Go context, our parsing context :)
	ctx := lcontext.New(options...)

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
	isTLS := sc.KeyFile != "" && sc.CertFile != ""
	options := []icontext.Option{
		icontext.WithResolver(rslv),
		icontext.WithMaxBackends(r.config.OverrideMaxBackends),
		icontext.WithMaxAcls(r.config.OverrideMaxAcls),
		icontext.WithActualResponse(sc.IsProxyResponse),
		icontext.WithTLServer(isTLS),
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
	// If simulator configuration has edge dictionaries, inject them
	if sc.OverrideEdgeDictionaries != nil {
		options = append(options, icontext.WithInjectEdgeDictionaries(sc.OverrideEdgeDictionaries))
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

	var err error
	if isTLS {
		writeln(green, "Simulator server starts on 0.0.0.0:%d with TLS", sc.Port)
		err = s.ListenAndServeTLS(sc.CertFile, sc.KeyFile)
	} else {
		writeln(green, "Simulator server starts on 0.0.0.0:%d", sc.Port)
		err = s.ListenAndServe()
	}
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
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
	if tc.OverrideEdgeDictionaries != nil {
		options = append(options, icontext.WithInjectEdgeDictionaries(tc.OverrideEdgeDictionaries))
	}

	// Factory override variables.
	// The order is imporotant, should do yaml -> cli order because cli could override yaml configuration
	overrides := make(map[string]any)
	if tc.YamlOverrideVariables != nil {
		maps.Copy(overrides, tc.YamlOverrideVariables)
	}
	if tc.CLIOverrideVariables != nil {
		for _, v := range tc.CLIOverrideVariables {
			key, val, parsed := r.parseOverrideVariables(v)
			if !parsed {
				continue
			}
			overrides[key] = val
		}
	}
	options = append(options, icontext.WithOverrideVariables(overrides))

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

func (r *Runner) parseOverrideVariables(v string) (string, any, bool) {
	sep := strings.SplitN(v, "=", 2)
	if len(sep) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(sep[0])
	val := strings.TrimSpace(sep[1])

	// Simple type assertion of primitive value
	if strings.EqualFold(val, "true") {
		return key, true, true // bool:true
	} else if strings.EqualFold(val, "false") {
		return key, false, true // bool:true
	} else if v, err := strconv.ParseInt(val, 10, 64); err != nil {
		return key, v, true // integer
	} else if v, err := strconv.ParseFloat(val, 64); err != nil {
		return key, v, true // float
	} else {
		return key, val, true // string
	}
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
