package main

const linterPredefinedVariables = `
// Code generated by __generator__/linter.go; DO NOT EDIT.

package context

import (
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/types"
)

var (
	ErrDeprecated              = errors.New("deprecated")
	ErrUncapturedRegexVariable = errors.New("uncaptured-regex-variable")
	ErrRegexVariableOverridden = errors.New("overridden-regex-variable")
)

func predefinedVariables() Variables {
	return {{ .Variables }}
}

func newRegexMatchedValues() map[string]int {
	return map[string]int{
		"re.group.0": 0,
		"re.group.1": 0,
		"re.group.2": 0,
		"re.group.3": 0,
		"re.group.4": 0,
		"re.group.5": 0,
		"re.group.6": 0,
		"re.group.7": 0,
		"re.group.8": 0,
		"re.group.9": 0,
		"re.group.10": 0,
	}
}`

const linterBuiltinFunctions = `
// Code generated by __generator__/linter.go; DO NOT EDIT.

package context

import (
	"github.com/ysugimoto/falco/types"
)

type Functions map[string]*FunctionSpec

type FunctionSpec struct {
	Items map[string]*FunctionSpec
	Value *BuiltinFunction
}

type BuiltinFunction struct {
	Arguments 						[][]types.Type
	Return    						types.Type
	Extra     						func(c *Context, name string) interface{}
	Scopes    						int
	Reference 						string
	IsUserDefinedFunction bool
}

func builtinFunctions() Functions {
	return {{ .Functions }}
}`

const simulatorPredefinedVariables = `
// Code generated by __generator__/simulator.go; DO NOT EDIT.

package variable

import (
	"github.com/ysugimoto/falco/simulator/types"
)

func PredefinedVariables() Variables {
	vs := Variables{}
	{{ .Variables }}
	return vs
}
`

const interpreterBuiltinFunctions = `
// Code generated by __generator__/interpreter.go; DO NOT EDIT.

package function

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/function/builtin"
)

var builtinFunctions = map[string]*Function {
	{{ .Functions }}
}
`

const interpreterFunctionImplementation = `
// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/function/errors"
)

const {{ .Name }}_Name = "{{ .Original }}"
var {{ .Name }}_ArgumentTypes = {{ .ArgumentTypes }}

func {{ .Name }}_Validate(args []value.Value) error {
	{{ if .NoArgument -}}
	if len(args) > 0 {
		return errors.ArgumentMustEmpty({{ .Name }}_Name, args)
	}
	{{ else if eq .MinArgs .MaxArgs -}}
	if len(args) != {{ .MinArgs }} {
		return errors.ArgumentNotEnough({{ .Name }}_Name, {{ .MinArgs }}, args)
	}
	{{ else -}}
	if len(args) < {{ .MinArgs }} || len(args) > {{ .MaxArgs }} {
		return errors.ArgumentNotInRange({{ .Name }}_Name, {{ .MinArgs }}, {{ .MaxArgs }}, args)
	}
	{{ end -}}

	{{ if not .NoArgument -}}
	for i := range args {
		if args[i].Type() != {{ .Name }}_ArgumentTypes[i] {
			return errors.TypeMismatch({{ .Name }}_Name, i+1, {{ .Name }}_ArgumentTypes[i], args[i].Type())
		}
	}
	{{ end -}}
	return nil
}

// Fastly built-in function implementation of {{ .Original }}
// Arguments may be:
{{- range .Arguments }}
// - {{ . }}
{{- end }}
// Reference: {{ .Reference }}
func {{ .Name }}(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := {{ .Name }}_Validate(args); err != nil {
		return value.Null, err
	}

	// Need to be implemented
	return value.Null, errors.NotImplemented("{{ .Original }}")
}

`

const interpreterFunctionTestImplementation = `
// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"testing"

	// "github.com/ysugimoto/falco/interpreter/context"
	// "github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of {{ .Original }}
// Arguments may be:
{{- range .Arguments }}
// - {{ . }}
{{- end }}
// Reference: {{ .Reference }}
func Test_{{ .Name }}(t *testing.T) {
	t.Skip("Test Builtin function {{ .Original }} should be impelemented")
}

`

const interpreterPredefinedVariables = `
// Code generated by __generator__/linter.go; DO NOT EDIT.

package variable

const (
{{ .Variables }}
)
`

const consoleSuggestions = `
// Code generated by __generator__/console.go; DO NOT EDIT.

package console

import (
	"github.com/c-bata/go-prompt"
)

var statementSuggestions = []prompt.Suggest{
	{{- range .Statements }}
	{{"{"}}Text: "{{ . }}", Description: "{{ . }} statement"{{"}"}},
	{{- end }}
}

var promptSuggestions = map[string][]prompt.Suggest{
	"INIT": {},
	{{- range $scope := .Scopes }}
	"{{ $scope }}": {
		{{- range filterByScope $scope $.Suggestions }}
		{{"{"}}Text: "{{ .Name }}", Description: "{{ .Description }}"{{"}"}},
		{{- end }}
	},
	{{- end }}
}
`
