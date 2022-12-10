package interpreter

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/simulator/variable"
)

func (i *Interpreter) ProcessSubroutine(sub *ast.SubroutineDeclaration) State {
	i.flows = append(i.flows, sub.Name.Value)
	defer func() {
		// reset all local variables and regex capture variables
		delete(i.vars, "var")
		delete(i.vars, "re")
	}()

	return i.ProcessBlockStatement(sub.Block.Statements)
}

func (i *Interpreter) ProcessFunctionSubroutine(sub *ast.SubroutineDeclaration) (variable.Value, State, error) {
	i.flows = append(i.flows, sub.Name.Value)
	// Store the current variables and restore after subroutine has ended
	storedVars := i.vars["var"]
	storedRe := i.vars["re"]
	delete(i.vars, "var")
	delete(i.vars, "re")
	defer func() {
		i.vars["var"] = storedVars
		i.vars["re"] = storedRe
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
				return variable.Null, state, nil
			}
		case *ast.CallStatement:
			var state State
			state, err = i.ProcessCallStatement(t)
			if state != NONE {
				return variable.Null, state, nil
			}
		case *ast.IfStatement:
			var state State
			state, err = i.ProcessIfStatement(t)
			if state != NONE {
				return variable.Null, state, nil
			}
		case *ast.RestartStatement:
			// restart statement force change state to RESTART
			return variable.Null, RESTART, nil
		case *ast.ReturnStatement:
			var val variable.Value
			var state State
			val, state, err = i.ProcessFunctionReturnStatement(t)
			// Functional subroutine can return state
			// https://developer.fastly.com/reference/vcl/subroutines/#returning-a-state
			if state != NONE {
				return variable.Null, state, nil
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
			return variable.Null, ERROR, nil

		// Others, no effects
		case *ast.EsiStatement:
			// Nothing to do, actually enable ESI in origin request
			break
		}
		if err != nil {
			i.err = errors.WithStack(err)
			return variable.Null, INTERNAL_ERROR, err
		}
	}

	return variable.Null, NONE, errors.WithStack(fmt.Errorf(
		"Functioncal subroutine %s may not return any values", sub.Name.Value,
	))
}

func (i *Interpreter) ProcessFunctionReturnStatement(stmt *ast.ReturnStatement) (variable.Value, State, error) {
	val, err := i.ProcessExpression(*stmt.ReturnExpression, false)
	if err != nil {
		return variable.Null, NONE, errors.WithStack(err)
	}
	if !val.IsLiteral() {
		return variable.Null, NONE, errors.WithStack(fmt.Errorf(
			"Functioncal subroutine only can return value only accepts a literal value",
		))
	}
	return val, NONE, nil
}
