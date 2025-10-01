package errors

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/token"
)

func New(name, format string, args ...any) error {
	return errors.WithStack(fmt.Errorf("["+name+"] "+format, args...))
}

func NotImplemented(name string) error {
	return New(name, "Not implemented")
}

func ArgumentAtLeast(name string, least int) error {
	return New(name, "At least %d arguments must be provided", least)
}

func ArgumentMustEmpty(name string, args []value.Value) error {
	return New(name, "Could not accept any arguments but %d provided", len(args))
}

func ArgumentNotEnough(name string, expects int, args []value.Value) error {
	return New(name, "Expects %d arguments but %d provided", expects, len(args))
}

func ArgumentNotInRange(name string, minArgs, maxArgs int, args []value.Value) error {
	return New(name, "Expects between %d and %d arguments but %d argument provided", minArgs, maxArgs, len(args))
}

func TypeMismatch(name string, num int, expects, actual value.Type) error {
	return New(name, "Argument %d expects %s type but %s provided", num, expects, actual)
}

func CannotConvertToString(name string, num int) error {
	return New(name, "Argument %d cannot convert to string because the value is literal", num)
}

// the error given when you querystring.get(req.url, "%ff");
// fastly error is "Unexpected byte 0x%02X in UTF-8 in short-string"
func UnexpectedByteInShortString(name string, num int) error {
	return New(name, "Argument %d, after pct-decoding, is invalid utf-8", num)
}

// the error given when you querystring.get(req.url, "%eh");
// fastly error is "Invalid hex char %c (0x%02X) in %%xx escape"
func InvalidHexChar(name string, num byte) error {
	return New(name, "Argument %d has invalid pct-encode sequence", num)
}

// Testing related errors
type TestingError struct {
	// Token info will be injected on interpreter
	Token   token.Token
	Message string
}

func NewTestingError(format string, args ...any) *TestingError {
	return &TestingError{
		Message: fmt.Sprintf(format, args...),
	}
}

func (e *TestingError) Error() string {
	return e.Message
}

type AssertionError struct {
	// Token info will be injected by interpreter
	Token   token.Token
	Actual  value.Value
	Message string
}

func NewAssertionError(actual value.Value, format string, args ...any) *AssertionError {
	return &AssertionError{
		Message: fmt.Sprintf(format, args...),
		Actual:  actual,
	}
}

func (e *AssertionError) Error() string {
	return "Assertion Error: " + e.Message
}
