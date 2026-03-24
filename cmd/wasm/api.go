//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"syscall/js"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/formatter"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter"
	"github.com/ysugimoto/falco/linter/context"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/token"
)

// parse parses VCL source code and returns the AST as JSON.
// JS: FalcoVCL.parse(vcl: string): ParseResult
func parse(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return toJS(ParseResult{Error: "parse requires a VCL string argument"})
	}

	vcl := args[0].String()

	lx := lexer.NewFromString(vcl)
	p := parser.New(lx)
	ast, err := p.ParseVCLOrSnippet()
	if err != nil {
		// Try to extract line/position from ParseError
		var parseErr *parser.ParseError
		if errors.As(err, &parseErr) {
			return toJS(ParseResult{
				Error: fmt.Sprintf("%s, line: %d, position: %d",
					parseErr.Message, parseErr.Token.Line, parseErr.Token.Position),
			})
		}
		return toJS(ParseResult{Error: err.Error()})
	}

	return toJS(ParseResult{AST: ast})
}

// tokenize extracts tokens from VCL source code.
// JS: FalcoVCL.tokenize(vcl: string): TokenizeResult
func tokenize(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return toJS(TokenizeResult{Error: "tokenize requires a VCL string argument"})
	}

	vcl := args[0].String()
	lx := lexer.NewFromString(vcl)

	var tokens []Token
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
			Category: tokenCategory(tok.Type),
		})
	}

	return toJS(TokenizeResult{Tokens: tokens})
}

// format formats VCL source code.
// JS: FalcoVCL.format(vcl: string, options?: FormatOptions): FormatResult
func format(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return toJS(FormatResult{Error: "format requires a VCL string argument"})
	}

	vcl := args[0].String()

	// Parse options if provided
	conf := defaultFormatConfig()
	if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
		applyFormatOptions(conf, args[1])
	}

	// Parse VCL to AST
	lx := lexer.NewFromString(vcl)
	p := parser.New(lx)
	ast, err := p.ParseVCLOrSnippet()
	if err != nil {
		return toJS(FormatResult{Error: "Parse error: " + err.Error()})
	}

	// Format
	f := formatter.New(conf)
	reader := f.Format(ast)
	if reader == nil {
		return toJS(FormatResult{Error: "Format failed: unsupported AST structure"})
	}

	formatted, err := io.ReadAll(reader)
	if err != nil {
		return toJS(FormatResult{Error: "Format error: " + err.Error()})
	}

	return toJS(FormatResult{Formatted: string(formatted)})
}

// lint analyzes VCL source code for errors and warnings.
// JS: FalcoVCL.lint(vcl: string, options?: LintOptions): LintResult
func lint(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return toJS(LintResult{Error: "lint requires a VCL string argument"})
	}

	vcl := args[0].String()

	// Parse options if provided
	var opts LintOptions
	if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
		opts = parseLintOptions(args[1])
	}

	// Parse VCL to AST
	lx := lexer.NewFromString(vcl)
	p := parser.New(lx)
	ast, err := p.ParseVCLOrSnippet()
	if err != nil {
		return toJS(LintResult{Error: "Parse error: " + err.Error()})
	}

	// Create linter context with scope if specified
	ctx := context.New()
	if opts.Scope != "" {
		scope := parseScope(opts.Scope)
		if scope > 0 {
			ctx.Scope(scope)
		}
	}

	// Lint with verbose mode to show all warnings and info
	linterConfig := &config.LinterConfig{
		VerboseWarning: true,
		VerboseInfo:    true,
	}
	l := linter.New(linterConfig)
	l.Lint(ast, ctx)

	// Collect errors
	var lintErrors []LintError
	if l.FatalError != nil {
		line, pos := 1, 1
		var parseErr *parser.ParseError
		if errors.As(l.FatalError.Error, &parseErr) {
			line = parseErr.Token.Line
			pos = parseErr.Token.Position
		}
		lintErrors = append(lintErrors, LintError{
			Severity: "error",
			Message:  l.FatalError.Error.Error(),
			Line:     line,
			Position: pos,
		})
	}

	for _, le := range l.Errors {
		lintErrors = append(lintErrors, LintError{
			Severity: strings.ToLower(string(le.Severity)),
			Message:  le.Message,
			Line:     le.Token.Line,
			Position: le.Token.Position,
			Rule:     string(le.Rule),
		})
	}

	return toJS(LintResult{Errors: lintErrors})
}

// toJS converts a Go struct to a JS object via JSON.
func toJS(v any) any {
	data, err := json.Marshal(v)
	if err != nil {
		return js.Global().Get("JSON").Call("parse", `{"error":"JSON marshal failed"}`)
	}
	return js.Global().Get("JSON").Call("parse", string(data))
}

// tokenCategory maps token types to semantic categories for syntax highlighting.
func tokenCategory(tt token.TokenType) string {
	switch tt {
	// Keywords
	case token.ACL, token.BACKEND, token.DIRECTOR, token.TABLE, token.SUBROUTINE,
		token.ADD, token.CALL, token.DECLARE, token.ERROR, token.ESI,
		token.INCLUDE, token.IMPORT, token.LOG, token.REMOVE, token.RESTART,
		token.RETURN, token.SET, token.SYNTHETIC, token.SYNTHETIC_BASE64, token.UNSET,
		token.IF, token.ELSE, token.ELSEIF, token.ELSIF,
		token.PENALTYBOX, token.RATECOUNTER, token.GOTO,
		token.SWITCH, token.CASE, token.DEFAULT, token.BREAK, token.FALLTHROUGH,
		token.PRAGMA:
		return "keyword"

	// Strings
	case token.STRING, token.OPEN_LONG_STRING, token.CLOSE_LONG_STRING:
		return "string"

	// Numbers
	case token.INT, token.FLOAT, token.RTIME:
		return "number"

	// Booleans
	case token.TRUE, token.FALSE:
		return "boolean"

	// Identifiers
	case token.IDENT:
		return "variable"

	// Operators
	case token.EQUAL, token.NOT_EQUAL, token.REGEX_MATCH, token.NOT_REGEX_MATCH,
		token.GREATER_THAN, token.LESS_THAN, token.GREATER_THAN_EQUAL, token.LESS_THAN_EQUAL,
		token.AND, token.OR, token.NOT,
		token.ASSIGN, token.ADDITION, token.SUBTRACTION, token.MULTIPLICATION,
		token.DIVISION, token.REMAINDER,
		token.BITWISE_OR, token.BITWISE_AND, token.BITWISE_XOR,
		token.LEFT_SHIFT, token.RIGHT_SHIFT, token.LEFT_ROTATE, token.RIGHT_ROTATE,
		token.LOGICAL_AND, token.LOGICAL_OR,
		token.PLUS, token.MINUS, token.SLASH, token.PERCENT:
		return "operator"

	// Comments
	case token.COMMENT:
		return "comment"

	// Punctuation
	case token.LEFT_BRACE, token.RIGHT_BRACE, token.LEFT_PAREN, token.RIGHT_PAREN,
		token.LEFT_BRACKET, token.RIGHT_BRACKET, token.COMMA, token.SEMICOLON,
		token.DOT, token.COLON:
		return "punctuation"

	// Control
	case token.FASTLY_CONTROL:
		return "control"

	default:
		return "text"
	}
}

// parseScope converts a scope string to the context scope constant.
func parseScope(s string) int {
	switch strings.ToLower(s) {
	case "recv":
		return context.RECV
	case "hash":
		return context.HASH
	case "hit":
		return context.HIT
	case "miss":
		return context.MISS
	case "pass":
		return context.PASS
	case "fetch":
		return context.FETCH
	case "error":
		return context.ERROR
	case "deliver":
		return context.DELIVER
	case "log":
		return context.LOG
	case "pipe":
		return context.PIPE
	default:
		return 0
	}
}

// defaultFormatConfig returns a FormatConfig with sensible defaults.
func defaultFormatConfig() *config.FormatConfig {
	return &config.FormatConfig{
		IndentWidth:                2,
		IndentStyle:                config.IndentStyleSpace,
		TrailingCommentWidth:       1,
		LineWidth:                  120,
		ExplicitStringConcat:       false,
		SortDeclarationProperty:    false,
		AlignDeclarationProperty:   false,
		ElseIf:                     false,
		AlwaysNextLineElseIf:       false,
		ReturnStatementParenthesis: true,
		SortDeclaration:            false,
		AlignTrailingComment:       false,
		CommentStyle:               config.CommentStyleNone,
		ShouldUseUnset:             false,
		IndentCaseLabels:           false,
	}
}

// applyFormatOptions updates the config from JS options object.
func applyFormatOptions(conf *config.FormatConfig, opts js.Value) {
	if v := opts.Get("indentWidth"); !v.IsUndefined() {
		conf.IndentWidth = v.Int()
	}
	if v := opts.Get("indentStyle"); !v.IsUndefined() {
		conf.IndentStyle = v.String()
	}
	if v := opts.Get("lineWidth"); !v.IsUndefined() {
		conf.LineWidth = v.Int()
	}
	if v := opts.Get("explicitStringConcat"); !v.IsUndefined() {
		conf.ExplicitStringConcat = v.Bool()
	}
	if v := opts.Get("sortDeclarationProperty"); !v.IsUndefined() {
		conf.SortDeclarationProperty = v.Bool()
	}
	if v := opts.Get("alignDeclarationProperty"); !v.IsUndefined() {
		conf.AlignDeclarationProperty = v.Bool()
	}
	if v := opts.Get("elseIf"); !v.IsUndefined() {
		conf.ElseIf = v.Bool()
	}
	if v := opts.Get("alwaysNextLineElseIf"); !v.IsUndefined() {
		conf.AlwaysNextLineElseIf = v.Bool()
	}
	if v := opts.Get("returnStatementParen"); !v.IsUndefined() {
		conf.ReturnStatementParenthesis = v.Bool()
	}
	if v := opts.Get("sortDeclaration"); !v.IsUndefined() {
		conf.SortDeclaration = v.Bool()
	}
	if v := opts.Get("alignTrailingComment"); !v.IsUndefined() {
		conf.AlignTrailingComment = v.Bool()
	}
	if v := opts.Get("commentStyle"); !v.IsUndefined() {
		conf.CommentStyle = v.String()
	}
	if v := opts.Get("shouldUseUnset"); !v.IsUndefined() {
		conf.ShouldUseUnset = v.Bool()
	}
	if v := opts.Get("indentCaseLabels"); !v.IsUndefined() {
		conf.IndentCaseLabels = v.Bool()
	}
}

// parseLintOptions extracts LintOptions from a JS object.
func parseLintOptions(opts js.Value) LintOptions {
	var o LintOptions
	if v := opts.Get("scope"); !v.IsUndefined() {
		o.Scope = v.String()
	}
	return o
}
