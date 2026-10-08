//go:build wasip1 && wasm

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ysugimoto/falco/v2/config"
	"github.com/ysugimoto/falco/v2/linter"
	lcontext "github.com/ysugimoto/falco/v2/linter/context"
	"github.com/ysugimoto/falco/v2/parser"
)

const cleanVCL = "sub vcl_recv {\n#FASTLY RECV\n  set req.http.X-Example = \"hello\";\n}\n"

// testResult mirrors RunnerResult's diagnostic fields but keeps Vcl opaque
// (its AST holds an interface that cannot be unmarshaled back from JSON). The
// here we only assert diagnostics.
type testResult struct {
	Infos       int
	Warnings    int
	Errors      int
	LintErrors  map[string][]*linter.LintError
	ParseErrors map[string]*parser.ParseError
	Vcl         json.RawMessage
}

// unmarshalResult decodes a doLint payload into a testResult.
func unmarshalResult(t *testing.T, out string) testResult {
	t.Helper()
	var r testResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("unmarshal RunnerResult: %v\npayload: %s", err, out)
	}
	return r
}

// TestDoLintClean lints a valid recv subroutine and expects an `ok` payload with
// no parse errors and no error-severity diagnostics.
func TestDoLintClean(t *testing.T) {
	out, err := doLint(cleanVCL, "")
	if err != nil {
		t.Fatalf("doLint error: %v", err)
	}
	r := unmarshalResult(t, out)
	if len(r.ParseErrors) != 0 {
		t.Fatalf("unexpected parse errors: %+v", r.ParseErrors)
	}
	if r.Errors != 0 {
		t.Fatalf("expected 0 errors on clean VCL, got %d", r.Errors)
	}
}

// TestDoLintLintError keys lint diagnostics under the synthetic input name and
// returns them as an `ok` payload (not a WIT err).
func TestDoLintLintError(t *testing.T) {
	src := "sub vcl_recv {\n#FASTLY RECV\n  set req.http.X-Bad = obj.does_not_exist;\n}\n"
	out, err := doLint(src, "")
	if err != nil {
		t.Fatalf("doLint error: %v", err)
	}
	r := unmarshalResult(t, out)
	if len(r.LintErrors[inputName]) == 0 {
		t.Fatalf("expected lint diagnostics keyed by %q, got %+v", inputName, r.LintErrors)
	}
}

// TestDoLintParseErrorIsOkPayload routes a parse error through ParseErrors as an
// `ok` payload, matching native `lint -json`.
func TestDoLintParseErrorIsOkPayload(t *testing.T) {
	out, err := doLint("sub vcl_recv {", "")
	if err != nil {
		t.Fatalf("doLint should not WIT-err on a parse error: %v", err)
	}
	r := unmarshalResult(t, out)
	if r.ParseErrors[inputName] == nil {
		t.Fatalf("expected ParseErrors[%q], got %+v", inputName, r.ParseErrors)
	}
}

// TestDoLintRuleOverride downgrades a diagnostic to IGNORE and confirms it is
// dropped from the counts.
func TestDoLintRuleOverride(t *testing.T) {
	src := "sub vcl_recv {\n#FASTLY RECV\n  set req.http.X-Bad = obj.does_not_exist;\n}\n"
	out, err := doLint(src, "")
	if err != nil {
		t.Fatalf("doLint error: %v", err)
	}
	base := unmarshalResult(t, out)
	var rule string
	for _, les := range base.LintErrors {
		if len(les) > 0 {
			rule = string(les[0].Rule)
			break
		}
	}
	if rule == "" {
		t.Skip("no rule-tagged diagnostic to override")
	}
	opts := `{"rules":{"` + rule + `":"IGNORE"}}`
	out2, err := doLint(src, opts)
	if err != nil {
		t.Fatalf("doLint (override) error: %v", err)
	}
	r2 := unmarshalResult(t, out2)
	for _, le := range r2.LintErrors[inputName] {
		if string(le.Rule) == rule {
			t.Fatalf("rule %q should have been ignored, still present", rule)
		}
	}
}

// TestDoLintResolvesIncludeFromOptions resolves a top-level include against the
// host-supplied includes map. A provided module resolves cleanly; a missing one
// surfaces an in-band diagnostic (it does not trap or WIT-err).
func TestDoLintResolvesIncludeFromOptions(t *testing.T) {
	src := `include "sub_mod";`
	opts := `{"includes":{"sub_mod":"sub vcl_recv {\n#FASTLY RECV\n}"}}`
	out, err := doLint(src, opts)
	if err != nil {
		t.Fatalf("doLint with provided include should resolve: %v", err)
	}
	r := unmarshalResult(t, out)
	if len(r.ParseErrors) != 0 {
		t.Fatalf("provided include should not produce parse errors: %+v", r.ParseErrors)
	}

	out2, err := doLint(src, "")
	if err != nil {
		t.Fatalf("missing include should be in-band, not a WIT err: %v", err)
	}
	r2 := unmarshalResult(t, out2)
	if len(r2.LintErrors) == 0 && len(r2.ParseErrors) == 0 {
		t.Fatal("missing include should produce a diagnostic")
	}
}

// TestDoLintRejectsUnknownScope surfaces an unknown scope as a WIT err.
func TestDoLintRejectsUnknownScope(t *testing.T) {
	if _, err := doLint(cleanVCL, `{"scope":"bogus"}`); err == nil {
		t.Fatal("expected err for unknown scope")
	}
}

// TestDoFormat formats valid VCL and rejects unparseable input.
func TestDoFormat(t *testing.T) {
	out, err := doFormat(cleanVCL, "")
	if err != nil {
		t.Fatalf("doFormat error: %v", err)
	}
	if !strings.Contains(out, "vcl_recv") {
		t.Fatalf("formatted output missing subroutine: %q", out)
	}
	if _, err := doFormat("sub vcl_recv {", ""); err == nil {
		t.Fatal("expected parse error from doFormat on invalid input")
	}
}

// TestDoParse returns a JSON AST for valid input and errs on invalid input.
func TestDoParse(t *testing.T) {
	out, err := doParse(cleanVCL)
	if err != nil {
		t.Fatalf("doParse error: %v", err)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("doParse output is not valid JSON: %q", out)
	}
	if _, err := doParse("sub vcl_recv {"); err == nil {
		t.Fatal("expected parse error from doParse on invalid input")
	}
}

// TestDoTokenize returns a JSON token array, and `[]` (not null) for empty input.
func TestDoTokenize(t *testing.T) {
	out, err := doTokenize(cleanVCL)
	if err != nil {
		t.Fatalf("doTokenize error: %v", err)
	}
	var toks []Token
	if err := json.Unmarshal([]byte(out), &toks); err != nil {
		t.Fatalf("unmarshal tokens: %v", err)
	}
	if len(toks) == 0 {
		t.Fatal("expected tokens for non-empty input")
	}
	// cleanVCL starts with `sub`; assert the shared token.Category mapping is
	// applied (the field is otherwise never checked).
	if toks[0].Category != "keyword" {
		t.Fatalf("first token category = %q, want \"keyword\"", toks[0].Category)
	}

	empty, err := doTokenize("")
	if err != nil {
		t.Fatalf("doTokenize(\"\") error: %v", err)
	}
	if empty != "[]" {
		t.Fatalf("empty input should tokenize to [], got %q", empty)
	}
}

// TestDoLintRejectsInvalidRuleSeverity surfaces a typo'd rule severity as a WIT
// err rather than silently ignoring it (the component has no stderr channel).
func TestDoLintRejectsInvalidRuleSeverity(t *testing.T) {
	if _, err := doLint(cleanVCL, `{"rules":{"some/rule":"warn"}}`); err == nil {
		t.Fatal("expected err for invalid rule severity value")
	}
}

// TestRecoverPanic verifies a panic in a do* function surfaces as a WIT err
// instead of an unrecoverable reactor trap.
func TestRecoverPanic(t *testing.T) {
	out, err := func() (out string, err error) {
		defer recoverPanic(&out, &err)
		panic("boom")
	}()
	if err == nil {
		t.Fatal("expected a recovered panic to surface as an error")
	}
	if !strings.Contains(err.Error(), "panic:") {
		t.Fatalf("recovered error should be tagged as a panic, got %q", err.Error())
	}
	if out != "" {
		t.Fatalf("out should be cleared on panic, got %q", out)
	}
}

func TestParseScope(t *testing.T) {
	if parseScope("recv") != lcontext.RECV {
		t.Fatal("recv scope mismatch")
	}
	if parseScope("FETCH") != lcontext.FETCH {
		t.Fatal("scope match should be case-insensitive")
	}
	if parseScope("bogus") != 0 {
		t.Fatal("unknown scope should be 0")
	}
}

func TestDecodeLintOptions(t *testing.T) {
	if _, err := decodeLintOptions("   "); err != nil {
		t.Fatalf("blank options should decode to zero value: %v", err)
	}
	o, err := decodeLintOptions(`{"scope":"recv","includePaths":["a","b"]}`)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if o.Scope != "recv" || len(o.IncludePaths) != 2 {
		t.Fatalf("unexpected options: %+v", o)
	}
	if _, err := decodeLintOptions("{not json"); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestApplyFormatConfig(t *testing.T) {
	conf := defaultFormatConfig()
	if err := applyFormatConfig(conf, `{"indentWidth":4,"indentStyle":"tab"}`); err != nil {
		t.Fatalf("applyFormatConfig error: %v", err)
	}
	if conf.IndentWidth != 4 || conf.IndentStyle != config.IndentStyleTab {
		t.Fatalf("config not applied: %+v", conf)
	}
	if err := applyFormatConfig(conf, "{bad"); err == nil {
		t.Fatal("expected error for invalid format config JSON")
	}
	if err := applyFormatConfig(defaultFormatConfig(), `{"indentStyle":"spaces"}`); err == nil {
		t.Fatal("expected error for invalid indentStyle value")
	}
	if err := applyFormatConfig(defaultFormatConfig(), `{"commentStyle":"bogus"}`); err == nil {
		t.Fatal("expected error for invalid commentStyle value")
	}
}
