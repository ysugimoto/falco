package linter

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/token"
	"github.com/ysugimoto/falco/types"
)

type Severity string

const (
	WARNING Severity = "Warning"
	ERROR   Severity = "Error"
	INFO    Severity = "Info"
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
		file = " in " + e.Token.File
	}

	msg := fmt.Sprintf(
		"[%s] %s%s%sat line: %d, position: %d%s",
		e.Severity, e.Message, rule, file, e.Token.Line, e.Token.Position, ref,
	)
	return msg
}

func InvalidName(t token.Token, name, ident string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf(`ident %s has invalid name of "%s"`, ident, name),
	}
}

func InvalidValue(t token.Token, tt, val string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf(`invalid %s value: %s`, tt, val),
	}
}

func InvalidType(t token.Token, name string, expect, actual types.Type) *LintError {
	return &LintError{
		Severity: WARNING,
		Token:    t,
		Message:  fmt.Sprintf("%s wants type %s but assign %s", name, expect.String(), actual.String()),
	}
}

func UndefinedVariable(t token.Token, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf(`variable "%s" is not defined`, name),
	}
}

func UndefinedAcl(t token.Token, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf(`acl "%s" is not defined`, name),
	}
}
func UndefinedBackend(t token.Token, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf(`backend "%s" is not defined`, name),
	}
}

func UndefinedSubroutine(t token.Token, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("Subroutine %s is not defined. If you have this subroutine, please define before call it", name),
	}
}

func InvalidOperation(t token.Token, name, operation string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("%s could not %s", name, operation),
	}
}

func Duplicated(t token.Token, name, ident string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf(`%s "%s" is duplicated`, ident, name),
	}
}

func AccessDenined(t token.Token, name, scope string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("could not access %s in scope %s", name, scope),
	}
}

func UndefinedFunction(t token.Token, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("function %s is undefined", name),
	}
}

func NotFunction(t token.Token, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("%s is not a function", name),
	}
}

func ErrorCodeRange(t token.Token, code int64) *LintError {
	return &LintError{
		Severity: INFO,
		Token:    t,
		Message:  fmt.Sprintf("code %d in error statemnt should use between 600-699", code),
	}
}

func InvalidTypeOperator(t token.Token, op string, expects ...types.Type) *LintError {
	es := make([]string, len(expects))
	for i, v := range expects {
		es[i] = v.String()
	}

	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf(`could not operand, "%s" operator expects type %s on right expression`, op, strings.Join(es, " or ")),
	}
}

func InvalidOperator(t token.Token, op string, left types.Type) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf(`operator "%s" could not use for %s`, op, left.String()),
	}
}

func InvalidTypeExpression(t token.Token, actual types.Type, expects ...types.Type) *LintError {
	es := make([]string, len(expects))
	for i, v := range expects {
		es[i] = v.String()
	}

	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("expression has type of %s but should have %s", actual.String(), strings.Join(es, " or ")),
	}
}

func InvalidTypeComparison(t token.Token, left, right types.Type) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("different type comparison between %s and %s", left.String(), right.String()),
	}
}

func ImplicitTypeConversion(t token.Token, from, to types.Type) *LintError {
	return &LintError{
		Severity: INFO,
		Token:    t,
		Message:  fmt.Sprintf("Type %s will treat as %s implicitly on string concatenation", from.String(), to.String()),
	}
}

func UndefinedBackendProperty(t token.Token, name string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("undefined backend property %s specified", name),
	}
}

func UndefinedDirectorProperty(t token.Token, name, dt string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("undefined director property %s for director type %s specified", name, dt),
	}
}

func UndefinedTableType(t token.Token, name, tt string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("undefined table type %s for %s", tt, name),
	}
}

func InvalidTypeConversion(t token.Token, vclType string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("type conversion failed, need to be able to cast as %s", vclType),
	}
}

func FunctionArgumentMismatch(t token.Token, name string, expect, actual int) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message:  fmt.Sprintf("function %s wants argument count %d but provides %d", name, expect, actual),
	}
}

func FunctionArgumentTypeMismatch(t token.Token, name string, num int, expect, actual types.Type) *LintError {
	suffix := "th"
	if num == 1 {
		suffix = "st"
	} else if num == 2 {
		suffix = "nd"
	}

	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message: fmt.Sprintf(
			"function %s wants argument %d%s as %s but applies %s",
			name, num, suffix, expect.String(), actual.String(),
		),
	}
}

func InvalidReturnState(t token.Token, scope, state string, expects ...string) *LintError {
	return &LintError{
		Severity: ERROR,
		Token:    t,
		Message: fmt.Sprintf(
			`return statement "%s" is invalid in %s, expects %s`,
			state, scope, strings.Join(expects, " or "),
		),
	}
}
