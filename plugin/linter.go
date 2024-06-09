package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/ast/codec"
)

type LintStatement interface {
	*ast.AclDeclaration |
		*ast.BackendDeclaration |
		*ast.DirectorDeclaration |
		*ast.TableDeclaration |
		*ast.SubroutineDeclaration |
		*ast.PenaltyboxDeclaration |
		*ast.RatecounterDeclaration |
		*ast.BlockStatement |
		*ast.ImportStatement |
		*ast.IncludeStatement |
		*ast.DeclareStatement |
		*ast.SetStatement |
		*ast.UnsetStatement |
		*ast.RemoveStatement |
		*ast.IfStatement |
		*ast.SwitchStatement |
		*ast.RestartStatement |
		*ast.EsiStatement |
		*ast.AddStatement |
		*ast.CallStatement |
		*ast.ErrorStatement |
		*ast.LogStatement |
		*ast.ReturnStatement |
		*ast.SyntheticStatement |
		*ast.SyntheticBase64Statement |
		*ast.GotoStatement |
		*ast.GotoDestinationStatement |
		*ast.FunctionCallStatement
}

type LinterRequest[T LintStatement] struct {
	Statement T
	Arguments []string
}

func ReadLinterRequest[T LintStatement](r io.Reader) (*LinterRequest[T], error) {
	decoder := codec.NewDecoder(r)
	statements, err := decoder.Decode()
	if err != nil {
		return nil, &LinterRequestError{
			Message: fmt.Sprintf("Failed to decode from input stream: %s", err),
		}
	} else if len(statements) == 0 {
		return nil, &LinterRequestError{
			Message: "Nothing statement from decoded AST",
		}
	}
	stmt, ok := statements[0].(T)
	if !ok {
		var name string
		if t := reflect.TypeOf(statements[0]); t.Kind() == reflect.Ptr {
			name = t.Elem().Name()
		} else {
			name = t.Name()
		}
		return nil, &LinterRequestError{
			Message: fmt.Sprintf("Type conversion failed, cannot convert %s statement", name),
		}
	}

	return &LinterRequest[T]{
		Arguments: os.Args[1:],
		Statement: stmt,
	}, nil
}

type LinterResponse struct {
	Errors []*Error `json:"errors"`
}

func (r *LinterResponse) Write(w io.Writer) error {
	return json.NewEncoder(w).Encode(r)
}

func (r *LinterResponse) Error(message string) {
	r.Errors = append(r.Errors, &Error{
		Severity: ERROR,
		Message:  message,
	})
}

func (r *LinterResponse) Warning(message string) {
	r.Errors = append(r.Errors, &Error{
		Severity: WARNING,
		Message:  message,
	})
}

func (r *LinterResponse) Info(message string) {
	r.Errors = append(r.Errors, &Error{
		Severity: INFO,
		Message:  message,
	})
}
