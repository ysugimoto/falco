package exception

import (
	"fmt"

	"github.com/ysugimoto/falco/token"
)

type Type string

const (
	RuntimeType Type = "RuntimeException"
	SystemType  Type = "SystemException"
)

type Exception struct {
	Type    Type
	Token   *token.Token
	Message string
}

func (e *Exception) Error() string {
	var file string
	var out string

	if e.Token == nil {
		out = fmt.Sprintf("[%s] %s", e.Type, e.Message)
	} else {
		t := *e.Token
		if t.File != "" {
			file = " in" + t.File
		}

		out = fmt.Sprintf("[%s] %s%s at line: %d, position: %d", e.Type, e.Message, file, t.Line, t.Position)
	}

	// SystemException means problem of falco implementation
	// Output additional message that report URL :-)
	if e.Type == SystemType {
		out += "\n\nThis exception is caused by falco interpreter."
		out += "\nIt maybe a bug, please report to http://github.com/ysugimoto/falco"
	}

	return out
}

func Runtime(token *token.Token, format string, args ...interface{}) *Exception {
	return &Exception{
		Type:    RuntimeType,
		Token:   token,
		Message: fmt.Sprintf(format, args...),
	}
}

func System(format string, args ...interface{}) *Exception {
	return &Exception{
		Type:    SystemType,
		Message: fmt.Sprintf(format, args...),
	}
}
