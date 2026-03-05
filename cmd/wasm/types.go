//go:build js && wasm

package main

// Token represents a lexical token with position and semantic info.
type Token struct {
	Type     string `json:"type"`
	Literal  string `json:"literal"`
	Line     int    `json:"line"`
	Position int    `json:"position"`
	Category string `json:"category"`
}

// TokenizeResult is the response from tokenize().
type TokenizeResult struct {
	Tokens []Token `json:"tokens"`
	Error  string  `json:"error,omitempty"`
}

// FormatResult is the response from format().
type FormatResult struct {
	Formatted string `json:"formatted"`
	Error     string `json:"error,omitempty"`
}

// LintError represents a single lint diagnostic.
type LintError struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Line     int    `json:"line"`
	Position int    `json:"position"`
	Rule     string `json:"rule,omitempty"`
}

// LintResult is the response from lint().
type LintResult struct {
	Errors []LintError `json:"errors"`
	Error  string      `json:"error,omitempty"`
}

// LintOptions configures linting behavior.
type LintOptions struct {
	Scope string `json:"scope,omitempty"` // recv, hash, hit, miss, pass, fetch, error, deliver, log, pipe
}

// ParseResult is the response from parse().
type ParseResult struct {
	AST   any    `json:"ast"`   // The VCL AST (nil if error)
	Error string `json:"error"` // Error message (empty if success)
}

// FormatOptions configures formatting behavior.
type FormatOptions struct {
	IndentWidth              int    `json:"indentWidth,omitempty"`
	IndentStyle              string `json:"indentStyle,omitempty"` // "space" or "tab"
	LineWidth                int    `json:"lineWidth,omitempty"`
	ExplicitStringConcat     bool   `json:"explicitStringConcat,omitempty"`
	SortDeclarationProperty  bool   `json:"sortDeclarationProperty,omitempty"`
	AlignDeclarationProperty bool   `json:"alignDeclarationProperty,omitempty"`
	ElseIf                   bool   `json:"elseIf,omitempty"`
	AlwaysNextLineElseIf     bool   `json:"alwaysNextLineElseIf,omitempty"`
	ReturnStatementParen     bool   `json:"returnStatementParen,omitempty"`
	SortDeclaration          bool   `json:"sortDeclaration,omitempty"`
	AlignTrailingComment     bool   `json:"alignTrailingComment,omitempty"`
	CommentStyle             string `json:"commentStyle,omitempty"` // "none", "slash", "sharp"
	ShouldUseUnset           bool   `json:"shouldUseUnset,omitempty"`
	IndentCaseLabels         bool   `json:"indentCaseLabels,omitempty"`
}
