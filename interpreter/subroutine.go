package interpreter

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
)

func (i *Interpreter) ProcessSubroutine(sub *ast.SubroutineDeclaration) (State, error) {
	i.process.Flows = append(i.process.Flows, process.NewFlow(i.ctx, sub))
	// reset all local values and regex capture values
	defer func() {
		i.ctx.RegexMatchedValues = make(map[string]*value.String)
		i.localVars = variable.LocalVariables{}
	}()

	return i.ProcessBlockStatement(sub.Block.Statements)
}

func (i *Interpreter) ProcessFunctionSubroutine(sub *ast.SubroutineDeclaration) (value.Value, State, error) {
	i.process.Flows = append(i.process.Flows, process.NewFlow(i.ctx, sub))

	// Store the current values and restore after subroutine has ended
	regex := i.ctx.RegexMatchedValues
	local := i.localVars
	i.ctx.RegexMatchedValues = make(map[string]*value.String)
	i.localVars = variable.LocalVariables{}

	defer func() {
		i.ctx.RegexMatchedValues = regex
		i.localVars = local
	}()

	var err error

	for _, stmt := range sub.Block.Statements {
		switch t := stmt.(type) {

		// Common logic statements (nothing to change state)
		case *ast.DeclareStatement:
			err = i.ProcessDeclareStatement(t)
		case *ast.SetStatement:
			err = i.ProcessSetStatement(t)
		case *ast.UnsetStatement:
			err = i.ProcessUnsetStatement(t)
		case *ast.RemoveStatement:
			err = i.ProcessRemoveStatement(t)
		case *ast.AddStatement:
			err = i.ProcessAddStatement(t)
		case *ast.LogStatement:
			err = i.ProcessLogStatement(t)
		case *ast.SyntheticStatement:
			err = i.ProcessSyntheticStatement(t)
		case *ast.SyntheticBase64Statement:
			err = i.ProcessSyntheticBase64Statement(t)
		// case *ast.GotoStatement:
		// 	err = i.ProcessGotoStatement(t)
		// case *ast.GotoDestinationStatement:
		// 	err = i.ProcessGotoDesticationStatement(t)
		// Probably change status statements
		case *ast.FunctionCallStatement:
			var state State
			state, err = i.ProcessFunctionCallStatement(t)
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.CallStatement:
			var state State
			state, err = i.ProcessCallStatement(t)
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.IfStatement:
			var state State
			state, err = i.ProcessIfStatement(t)
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.RestartStatement:
			// restart statement force change state to RESTART
			return value.Null, RESTART, nil
		case *ast.ReturnStatement:
			var val value.Value
			var state State
			val, state, err = i.ProcessFunctionReturnStatement(t)
			if err != nil {
				return val, state, errors.WithStack(err)
			}
			// Functional subroutine can return state
			// https://developer.fastly.com/reference/vcl/subroutines/#returning-a-state
			if state != NONE {
				return value.Null, state, nil
			}
			// Check return value type is the same
			if string(val.Type()) != sub.ReturnType.Value {
				return val, NONE, errors.WithStack(fmt.Errorf(
					"Invalid return type, expects=%s, but got=%s",
					sub.ReturnType.Value,
					val.Type(),
				))
			}
			return val, NONE, nil
		case *ast.ErrorStatement:
			// restart statement force change state to ERROR
			i.ProcessErrorStatement(t)
			return value.Null, ERROR, nil

		// Others, no effects
		case *ast.EsiStatement:
			// Nothing to do, actually enable ESI in origin request
			break
		}
		if err != nil {
			return value.Null, INTERNAL_ERROR, errors.WithStack(err)
		}
	}

	return value.Null, NONE, errors.WithStack(fmt.Errorf(
		"Functioncal subroutine %s did not return any values", sub.Name.Value,
	))
}

func (i *Interpreter) ProcessFunctionReturnStatement(stmt *ast.ReturnStatement) (value.Value, State, error) {
	val, err := i.ProcessExpression(*stmt.ReturnExpression, false)
	if err != nil {
		return value.Null, NONE, errors.WithStack(err)
	}
	if !val.IsLiteral() {
		return value.Null, NONE, errors.WithStack(fmt.Errorf(
			"Functioncal subroutine only can return value only accepts a literal value",
		))
	}

	switch t := val.(type) {
	case *value.Ident:
		if v, ok := stateMap[t.Value]; ok {
			return value.Null, v, nil
		}
		return value.Null, NONE, errors.WithStack(fmt.Errorf(
			"Unexpected return state value: %s", t.Value,
		))
	default:
		return val, NONE, nil
	}
}
