//go:build wasip1 && wasm

// Command falco-component is a WASI Component Model ("reactor") build of falco
// exposing lint / format / parse / tokenize as typed WIT functions (wit/falco.wit).
// It is string-in / string-out: the host instantiates it once and calls the
// exports repeatedly.
// The canonical-ABI glue lives in abi.go; this file holds the do* implementations.
// See docs/wasm-component.md.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/config"
	"github.com/ysugimoto/falco/v2/formatter"
	"github.com/ysugimoto/falco/v2/lexer"
	"github.com/ysugimoto/falco/v2/linter"
	lcontext "github.com/ysugimoto/falco/v2/linter/context"
	"github.com/ysugimoto/falco/v2/parser"
	"github.com/ysugimoto/falco/v2/resolver"
	"github.com/ysugimoto/falco/v2/token"
)

// inputName is the synthetic file name used as the map key in output, standing
// in for the absent filesystem so the RunnerResult JSON shape is preserved.
const inputName = "input.vcl"

// VCL mirrors cmd/falco.VCL so the serialized JSON shape is identical.
type VCL struct {
	File string
	AST  *ast.VCL
}

// RunnerResult mirrors cmd/falco.RunnerResult (the struct `lint -json`
// serializes) so the emitted JSON shape matches. Kept in sync with
// cmd/falco/runner.go.
type RunnerResult struct {
	Infos    int
	Warnings int
	Errors   int

	LintErrors  map[string][]*linter.LintError
	ParseErrors map[string]*parser.ParseError

	Vcl *VCL
}

// lintOptions is the JSON decoded from the WIT `options` argument of lint.
// Includes/IncludePaths let the host resolve `include` statements without a
// filesystem by supplying each reachable module's source up front; the
// component discovers transitive includes itself.
type lintOptions struct {
	Scope        string            `json:"scope"`
	Rules        map[string]string `json:"rules"`
	Includes     map[string]string `json:"includes"`
	IncludePaths []string          `json:"includePaths"`
}

// main never completes: this is a -buildmode=c-shared reactor, so the host runs
// package init and then calls the //go:wasmexport functions in abi.go directly.
func main() {}

// recoverPanic converts a panic in a do* function into a WIT `err` so one
// malformed request cannot trap and brick the reactor for later calls.
func recoverPanic(out *string, err *error) {
	if r := recover(); r != nil {
		*out = ""
		*err = fmt.Errorf("panic: %v", r)
	}
}

// doLint lints source in-memory and returns the RunnerResult as JSON. A parse
// error is reported through ParseErrors (matching native `lint -json`), so it
// is a normal `ok` payload rather than a WIT `err`.
func doLint(source, options string) (out string, err error) {
	defer recoverPanic(&out, &err)
	opts, err := decodeLintOptions(options)
	if err != nil {
		return "", err
	}

	result := &RunnerResult{
		LintErrors:  map[string][]*linter.LintError{},
		ParseErrors: map[string]*parser.ParseError{},
	}

	vcl, perr := parseSource(source)
	if perr != nil {
		var pe *parser.ParseError
		if errors.As(perr, &pe) {
			// Key by pe.Token.File, matching cmd/falco/runner.go.
			result.ParseErrors[pe.Token.File] = pe
			return marshal(result)
		}
		return "", perr
	}

	// An empty config produces the full diagnostic set; severity overrides are
	// applied below via buildOverrides.
	lc := &config.LinterConfig{}

	// Resolve `include` statements against the host-supplied module map. With no
	// includes this behaves like an empty resolver (an include fails to resolve).
	ctx := lcontext.New(lcontext.WithResolver(
		resolver.NewMapResolver(inputName, source, opts.Includes, opts.IncludePaths),
	))
	if opts.Scope != "" {
		scope := parseScope(opts.Scope)
		if scope == 0 {
			return "", fmt.Errorf("unknown scope %q", opts.Scope)
		}
		ctx.Scope(scope)
	}

	lt := linter.New(lc)
	lt.Lint(vcl, ctx)

	if lt.FatalError != nil {
		var pe *parser.ParseError
		if errors.As(lt.FatalError.Error, &pe) {
			result.ParseErrors[pe.Token.File] = pe
			return marshal(result)
		}
		// Surface a non-parse fatal error as a WIT err so it stays visible to the
		// host rather than returning an empty, clean-looking result.
		return "", fmt.Errorf("lint failed: %w", lt.FatalError.Error)
	}

	overrides, err := buildOverrides(opts.Rules)
	if err != nil {
		return "", err
	}
	for _, le := range lt.Errors {
		severity := le.Severity
		if v, found := overrides[string(le.Rule)]; found {
			severity = v
		}
		if severity == linter.IGNORE {
			continue
		}
		if le.Token.File == "" {
			le.Token.File = inputName
		}
		result.LintErrors[le.Token.File] = append(result.LintErrors[le.Token.File], le)
		switch severity {
		case linter.ERROR:
			result.Errors++
		case linter.WARNING:
			result.Warnings++
		case linter.INFO:
			result.Infos++
		}
	}

	result.Vcl = &VCL{File: inputName, AST: vcl}
	return marshal(result)
}

// doFormat formats source and returns the formatted VCL string.
func doFormat(source, confJSON string) (out string, err error) {
	defer recoverPanic(&out, &err)
	conf := defaultFormatConfig()
	if err := applyFormatConfig(conf, confJSON); err != nil {
		return "", err
	}

	vcl, perr := parseSource(source)
	if perr != nil {
		return "", fmt.Errorf("parse error: %w", perr)
	}

	reader := formatter.New(conf).Format(vcl)
	if reader == nil {
		return "", errors.New("format failed: unsupported AST structure")
	}
	formatted, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("format error: %w", err)
	}
	return string(formatted), nil
}

// doParse parses source and returns the AST as JSON.
func doParse(source string) (out string, err error) {
	defer recoverPanic(&out, &err)
	vcl, perr := parseSource(source)
	if perr != nil {
		return "", fmt.Errorf("parse error: %w", perr)
	}
	return marshal(vcl)
}

// Token mirrors ./cmd/wasm.Token so the per-token JSON shape matches the JS
// build. Per wit/falco.wit, tokenize returns a bare JSON array (no envelope).
type Token struct {
	Type     string `json:"type"`
	Literal  string `json:"literal"`
	Line     int    `json:"line"`
	Position int    `json:"position"`
	Category string `json:"category"`
}

// doTokenize lexes source and returns the tokens as a JSON array.
func doTokenize(source string) (out string, err error) {
	defer recoverPanic(&out, &err)
	lx := lexer.NewFromString(source, lexer.WithFile(inputName))
	tokens := []Token{} // non-nil so empty input marshals to `[]`, not `null`
	for {
		tok := lx.NextToken()
		if tok.Type == token.EOF {
			break
		}
		tokens = append(tokens, Token{
			Type:     string(tok.Type),
			Literal:  tok.Literal,
			Line:     tok.Line,
			Position: tok.Position,
			Category: token.Category(tok.Type),
		})
	}
	return marshal(tokens)
}

func parseSource(source string) (*ast.VCL, error) {
	lx := lexer.NewFromString(source, lexer.WithFile(inputName))
	return parser.New(lx).ParseVCLOrSnippet()
}

func decodeLintOptions(s string) (lintOptions, error) {
	var o lintOptions
	if strings.TrimSpace(s) == "" {
		return o, nil
	}
	if err := json.Unmarshal([]byte(s), &o); err != nil {
		return o, fmt.Errorf("invalid lint options JSON: %w", err)
	}
	return o, nil
}

// buildOverrides maps JSON rule-severity strings to linter severities. An
// unrecognized value errors out: the component has no stderr channel, so a
// silently-ignored typo would leave a host's rule config a no-op with no signal.
func buildOverrides(rules map[string]string) (map[string]linter.Severity, error) {
	overrides := map[string]linter.Severity{}
	for key, value := range rules {
		switch strings.ToUpper(value) {
		case "ERROR":
			overrides[key] = linter.ERROR
		case "WARNING":
			overrides[key] = linter.WARNING
		case "INFO":
			overrides[key] = linter.INFO
		case "IGNORE":
			overrides[key] = linter.IGNORE
		default:
			return nil, fmt.Errorf("invalid severity %q for rule %q (want ERROR|WARNING|INFO|IGNORE)", value, key)
		}
	}
	return overrides, nil
}

func marshal(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func parseScope(s string) int {
	switch strings.ToLower(s) {
	case "recv":
		return lcontext.RECV
	case "hash":
		return lcontext.HASH
	case "hit":
		return lcontext.HIT
	case "miss":
		return lcontext.MISS
	case "pass":
		return lcontext.PASS
	case "fetch":
		return lcontext.FETCH
	case "error":
		return lcontext.ERROR
	case "deliver":
		return lcontext.DELIVER
	case "log":
		return lcontext.LOG
	case "pipe":
		return lcontext.PIPE
	default:
		return 0
	}
}

func defaultFormatConfig() *config.FormatConfig {
	return &config.FormatConfig{
		IndentWidth:                2,
		IndentStyle:                config.IndentStyleSpace,
		TrailingCommentWidth:       1,
		LineWidth:                  120,
		ExplicitStringConcat:       true,
		ReturnStatementParenthesis: true,
		CommentStyle:               config.CommentStyleNone,
		BreakCompoundConditions:    true,
	}
}

// formatConfigJSON mirrors the FormatOptions field names accepted by ./cmd/wasm.
type formatConfigJSON struct {
	IndentWidth              *int    `json:"indentWidth"`
	IndentStyle              *string `json:"indentStyle"`
	LineWidth                *int    `json:"lineWidth"`
	ExplicitStringConcat     *bool   `json:"explicitStringConcat"`
	SortDeclarationProperty  *bool   `json:"sortDeclarationProperty"`
	AlignDeclarationProperty *bool   `json:"alignDeclarationProperty"`
	ElseIf                   *bool   `json:"elseIf"`
	AlwaysNextLineElseIf     *bool   `json:"alwaysNextLineElseIf"`
	ReturnStatementParen     *bool   `json:"returnStatementParen"`
	SortDeclaration          *bool   `json:"sortDeclaration"`
	AlignTrailingComment     *bool   `json:"alignTrailingComment"`
	CommentStyle             *string `json:"commentStyle"`
	ShouldUseUnset           *bool   `json:"shouldUseUnset"`
	IndentCaseLabels         *bool   `json:"indentCaseLabels"`
	BreakCompoundConditions  *bool   `json:"breakCompoundConditions"`
}

func applyFormatConfig(conf *config.FormatConfig, s string) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var o formatConfigJSON
	if err := json.Unmarshal([]byte(s), &o); err != nil {
		return fmt.Errorf("invalid format config JSON: %w", err)
	}
	if o.IndentWidth != nil {
		conf.IndentWidth = *o.IndentWidth
	}
	if o.IndentStyle != nil {
		switch *o.IndentStyle {
		case config.IndentStyleSpace, config.IndentStyleTab:
			conf.IndentStyle = *o.IndentStyle
		default:
			return fmt.Errorf("invalid indentStyle %q (want %q or %q)",
				*o.IndentStyle, config.IndentStyleSpace, config.IndentStyleTab)
		}
	}
	if o.LineWidth != nil {
		conf.LineWidth = *o.LineWidth
	}
	if o.ExplicitStringConcat != nil {
		conf.ExplicitStringConcat = *o.ExplicitStringConcat
	}
	if o.SortDeclarationProperty != nil {
		conf.SortDeclarationProperty = *o.SortDeclarationProperty
	}
	if o.AlignDeclarationProperty != nil {
		conf.AlignDeclarationProperty = *o.AlignDeclarationProperty
	}
	if o.ElseIf != nil {
		conf.ElseIf = *o.ElseIf
	}
	if o.AlwaysNextLineElseIf != nil {
		conf.AlwaysNextLineElseIf = *o.AlwaysNextLineElseIf
	}
	if o.ReturnStatementParen != nil {
		conf.ReturnStatementParenthesis = *o.ReturnStatementParen
	}
	if o.SortDeclaration != nil {
		conf.SortDeclaration = *o.SortDeclaration
	}
	if o.AlignTrailingComment != nil {
		conf.AlignTrailingComment = *o.AlignTrailingComment
	}
	if o.CommentStyle != nil {
		switch *o.CommentStyle {
		case config.CommentStyleNone, config.CommentStyleSlash, config.CommentStyleSharp:
			conf.CommentStyle = *o.CommentStyle
		default:
			return fmt.Errorf("invalid commentStyle %q (want %q, %q or %q)", *o.CommentStyle,
				config.CommentStyleNone, config.CommentStyleSlash, config.CommentStyleSharp)
		}
	}
	if o.ShouldUseUnset != nil {
		conf.ShouldUseUnset = *o.ShouldUseUnset
	}
	if o.IndentCaseLabels != nil {
		conf.IndentCaseLabels = *o.IndentCaseLabels
	}
	if o.BreakCompoundConditions != nil {
		conf.BreakCompoundConditions = *o.BreakCompoundConditions
	}
	return nil
}
