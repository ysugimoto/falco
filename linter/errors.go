package linter

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/token"
	"github.com/ysugimoto/falco/types"
)

type Severity string

const (
	WARNING Severity = "Warning"
	ERROR   Severity = "Error"
	INFO    Severity = "Info"
	IGNORE  Severity = "Ignore"
)

type LintError struct {
	Severity  Severity
	Token     token.Token
	Message   string
	Reference string
	Rule      Rule
}

func (l *LintError) Match(r Rule) *LintError {
	l.Rule = r
	l.Reference = r.Reference()
	return l
}

func (e *LintError) Ref(url string) *LintError {
	e.Reference = url
	return e
}

func (e *LintError) Error() string {
	var rule, ref, file string

	if e.Rule != "" {
		rule = fmt.Sprintf(" (%s)", e.Rule)
	}
	if e.Reference != "" {
		ref = "\ndocument: " + e.Reference
	}
	if e.Token.File != "" {
		file = " in" + e.Token.File
	}

	msg := fmt.Sprintf(
		"[%s] %s%s%s at line: %d, position: %d%s",
		e.Severity, e.Message, rule, file, e.Token.Line, e.Token.Position, ref,
	)
	return msg
}

func InvalidName(m *ast.Meta, name, ident string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`ident %s has invalid name of "%s"`, ident, name),
	}
}

func InvalidValue(m *ast.Meta, tt, val string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`invalid %s value: %s`, tt, val),
	}
}

func InvalidType(m *ast.Meta, name string, expect, actual types.Type) *LintError {
	return &LintError{
		Severity: WARNING,
		Token:    m.Token,
		Message:  fmt.Sprintf("%s wants type %s but assign %s", name, expect.String(), actual.String()),
	}
}

func UndefinedVariable(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`variable "%s" is not defined`, name),
	}
}

func UndefinedAcl(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`acl "%s" is not defined`, name),
	}
}
func UndefinedBackend(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`backend "%s" is not defined`, name),
	}
}

func UndefinedSubroutine(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("Subroutine %s is not defined. If you have this subroutine, please define before call it", name),
	}
}

func InvalidOperation(m *ast.Meta, name, operation string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("%s could not %s", name, operation),
	}
}

func Duplicated(m *ast.Meta, name, ident string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`%s "%s" is duplicated`, ident, name),
	}
}

func AccessDenined(m *ast.Meta, name, scope string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("could not access %s in scope %s", name, scope),
	}
}

func UndefinedFunction(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("function %s is undefined", name),
	}
}

func NotFunction(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("%s is not a function", name),
	}
}

func ErrorCodeRange(m *ast.Meta, code int64) *LintError {
	return &LintError{
		Severity: INFO,
		Token:    m.Token,
		Message:  fmt.Sprintf("code %d in error statemnt should use between 600-699", code),
	}
}

// FIXME: accept *ast.Meta
func InvalidTypeOperator(m *ast.Meta, op string, expects ...types.Type) *LintError {
	es := make([]string, len(expects))
	for i, v := range expects {
		es[i] = v.String()
	}

	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`could not operand, "%s" operator expects type %s on right expression`, op, strings.Join(es, " or ")),
	}
}

// FIXME: accept *ast.Meta
func InvalidOperator(m *ast.Meta, op string, left types.Type) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf(`operator "%s" could not use for %s`, op, left.String()),
	}
}

func InvalidTypeExpression(m *ast.Meta, actual types.Type, expects ...types.Type) *LintError {
	es := make([]string, len(expects))
	for i, v := range expects {
		es[i] = v.String()
	}

	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("expression has type of %s but should have %s", actual.String(), strings.Join(es, " or ")),
	}
}

func InvalidTypeComparison(m *ast.Meta, left, right types.Type) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("different type comparison between %s and %s", left.String(), right.String()),
	}
}

func ImplicitTypeConversion(m *ast.Meta, from, to types.Type) *LintError {
	return &LintError{
		Severity: INFO,
		Token:    m.Token,
		Message:  fmt.Sprintf("Type %s will treat as %s implicitly on string concatenation", from.String(), to.String()),
	}
}

func UndefinedBackendProperty(m *ast.Meta, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("undefined backend property %s specified", name),
	}
}

func UndefinedDirectorProperty(m *ast.Meta, name, dt string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("undefined director property %s for director type %s specified", name, dt),
	}
}

func UndefinedTableType(m *ast.Meta, name, tt string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("undefined table type %s for %s", tt, name),
	}
}

func InvalidTypeConversion(m *ast.Meta, vclType string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("type conversion failed, need to be able to cast as %s", vclType),
	}
}

func FunctionArgumentMismatch(m *ast.Meta, name string, expect, actual int) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message:  fmt.Sprintf("function %s wants argument count %d but provides %d", name, expect, actual),
	}
}

func FunctionArgumentTypeMismatch(m *ast.Meta, name string, num int, expect, actual types.Type) *LintError {
	suffix := "th"
	if num == 1 {
		suffix = "st"
	} else if num == 2 {
		suffix = "nd"
	}

	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message: fmt.Sprintf(
			"function %s wants argument %d%s as %s but applies %s",
			name, num, suffix, expect.String(), actual.String(),
		),
	}
}

func InvalidReturnState(m *ast.Meta, scope, state string, expects ...string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    m.Token,
		Message: fmt.Sprintf(
			`return statement "%s" is invalid in %s, expects %s`,
			state, scope, strings.Join(expects, " or "),
		),
	}
}
