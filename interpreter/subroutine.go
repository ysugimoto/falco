package interpreter

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/interpreter/assign"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/exception"
	"github.com/ysugimoto/falco/v2/interpreter/process"
	"github.com/ysugimoto/falco/v2/interpreter/value"
	"github.com/ysugimoto/falco/v2/interpreter/variable"
)

const (
	// Faslty does not document about max call stack but we define our expected stack count.
	// Fastly forbid VCL that may cause an infinite loop to call subroutine but our interpreter could accept,
	// so we need to suppress its behavior by definition and guard process.
	maxCallStackExceedCount = 100
)

func (i *Interpreter) ProcessSubroutine(sub *ast.SubroutineDeclaration, ds DebugState, args []value.Value) (State, error) {
	i.process.Flows = append(i.process.Flows, process.NewFlow(i.ctx, process.WithSubroutine(sub)))

	// Store the current values and restore after subroutine has ended
	regex := i.ctx.RegexMatchedValues
	local := i.localVars
	i.ctx.RegexMatchedValues = make(map[string]*value.String)
	i.localVars = variable.LocalVariables{}

	// Validate arguments and set as local variables
	if err := i.validateAndSetParameters(sub, args); err != nil {
		return NONE, errors.WithStack(err)
	}

	// Push this subroutine to callstacks
	i.callStack = append(i.callStack, sub)
	// If expected stack count is exceeded, raise an error
	if len(i.callStack) > maxCallStackExceedCount {
		return NONE, errors.WithStack(exception.MaxCallStackExceeded(&sub.GetMeta().Token, i.callStack))
	}

	defer func() {
		i.ctx.RegexMatchedValues = regex
		i.localVars = local
		i.ctx.SubroutineCalls[sub.Name.Value]++
		// Pop call stack
		i.callStack = i.callStack[:len(i.callStack)-1]
	}()

	// Try to extract fastly reserved subroutine macro
	if err := i.extractBoilerplateMacro(sub); err != nil {
		return NONE, errors.WithStack(err)
	}

	statements, err := i.resolveIncludeStatement(sub.Block.Statements, false)
	if err != nil {
		return NONE, errors.WithStack(err)
	}

	// Ignore debug status and must return state, not a value
	_, state, _, err := i.ProcessBlockStatement(statements, ds, false)
	return state, err
}

// nolint: gocognit, funlen
func (i *Interpreter) ProcessFunctionSubroutine(sub *ast.SubroutineDeclaration, ds DebugState, args []value.Value) (value.Value, State, error) {
	i.process.Flows = append(i.process.Flows, process.NewFlow(i.ctx, process.WithSubroutine(sub)))

	// Store the current values and restore after subroutine has ended
	regex := i.ctx.RegexMatchedValues
	local := i.localVars
	i.ctx.RegexMatchedValues = make(map[string]*value.String)
	i.localVars = variable.LocalVariables{}

	// Validate arguments and set as local variables
	if err := i.validateAndSetParameters(sub, args); err != nil {
		return value.Null, NONE, errors.WithStack(err)
	}

	// Push this subroutine to callstacks
	i.callStack = append(i.callStack, sub)
	// If expected stack count is exceeded, raise an error
	if len(i.callStack) > maxCallStackExceedCount {
		return value.Null, NONE, errors.WithStack(exception.MaxCallStackExceeded(&sub.GetMeta().Token, i.callStack))
	}

	defer func() {
		i.ctx.RegexMatchedValues = regex
		i.localVars = local
		i.ctx.SubroutineCalls[sub.Name.Value]++
		// Pop call stack
		i.callStack = i.callStack[:len(i.callStack)-1]
	}()

	var err error
	var debugState = ds

	for _, stmt := range sub.Block.Statements {
		// Call debugger
		if debugState != DebugStepOut {
			debugState = i.Debugger.Run(stmt)
		}

		// Find process marker and add flow if found
		if name, found := findProcessMark(stmt.GetMeta().Leading); found {
			i.process.Flows = append(
				i.process.Flows,
				process.NewFlow(i.ctx, process.WithName(name), process.WithToken(stmt.GetMeta().Token)),
			)
		}

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
		case *ast.BlockStatement:
			var val value.Value
			var state State
			val, state, _, err = i.ProcessBlockStatement(t.Statements, ds, true)
			if val != value.Null {
				return val, NONE, nil
			}
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.FunctionCallStatement:
			var state State
			// Enable breakpoint if current debug state is step-in
			if debugState == DebugStepIn {
				state, err = i.ProcessFunctionCallStatement(t, DebugStepIn)
			} else {
				state, err = i.ProcessFunctionCallStatement(t, DebugStepOut)
			}
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.CallStatement:
			var state State
			// Enable breakpoint if current debug state is step-in
			if debugState == DebugStepIn {
				state, err = i.ProcessCallStatement(t, DebugStepIn)
			} else {
				state, err = i.ProcessCallStatement(t, DebugStepOut)
			}
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.IfStatement:
			var val value.Value
			var state State
			// If statement inside functional subroutine could return value
			val, state, err = i.ProcessIfStatement(t, debugState, true)
			if val != value.Null {
				return val, NONE, nil
			}
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.SwitchStatement:
			var val value.Value
			var state State
			val, state, err = i.ProcessSwitchStatement(t, debugState, true)
			if val != value.Null {
				return val, NONE, nil
			}
			if state != NONE {
				return value.Null, state, nil
			}
		case *ast.RestartStatement:
			// restart statement force change state to RESTART
			return value.Null, RESTART, nil
		case *ast.ReturnStatement:
			var val value.Value
			var state State
			val, state, err = i.ProcessExpressionReturnStatement(t)
			if err != nil {
				return val, state, errors.WithStack(err)
			}
			// Functional subroutine can return state
			// https://developer.fastly.com/reference/vcl/subroutines/#returning-a-state
			if state != NONE {
				return value.Null, state, nil
			}
			// Check return value type and perform implicit conversion if needed
			expectedType := value.Type(sub.ReturnType.Value)
			converted, err := convertValueToType(val, expectedType)
			if err != nil {
				return val, NONE, exception.Runtime(
					&t.GetMeta().Token,
					"Invalid return type, expects=%s, but got=%s. Conversion failed: %s",
					sub.ReturnType.Value,
					val.Type(),
					err.Error(),
				)
			}
			return converted, NONE, nil
		case *ast.ErrorStatement:
			// error statement force change state to ERROR
			err = i.ProcessErrorStatement(t)
			if err == nil {
				return value.Null, ERROR, nil
			}
		case *ast.EsiStatement:
			if err := i.ProcessEsiStatement(t); err != nil {
				return value.Null, ERROR, nil
			}
		}
		if err != nil {
			return value.Null, INTERNAL_ERROR, errors.WithStack(err)
		}
	}

	return value.Null, NONE, exception.Runtime(
		&sub.GetMeta().Token,
		"Functional subroutine %s did not return any values",
		sub.Name.Value,
	)
}

func (i *Interpreter) ProcessExpressionReturnStatement(stmt *ast.ReturnStatement) (value.Value, State, error) {
	val, err := i.ProcessExpression(stmt.ReturnExpression)
	if err != nil {
		return value.Null, NONE, errors.WithStack(err)
	}

	switch t := val.(type) {
	case *value.Ident:
		if v, ok := stateMap[t.Value]; ok {
			return value.Null, v, nil
		}
		return value.Null, NONE, exception.Runtime(
			&stmt.GetMeta().Token,
			"Unexpected return state value: %s", t.Value,
		)
	default:
		return val, NONE, nil
	}
}

func (i *Interpreter) extractBoilerplateMacro(sub *ast.SubroutineDeclaration) error {
	if i.ctx.FastlySnippets == nil {
		return nil
	}

	// If subroutine name is fastly subroutine, find and extract boilerplate macro
	macro, ok := context.FastlyReservedSubroutine[sub.Name.Value]
	if !ok {
		return nil
	}
	snippets, ok := i.ctx.FastlySnippets.ScopedSnippets[macro]
	if !ok || len(snippets) == 0 {
		return nil
	}

	macroName := strings.ToUpper("fastly " + macro)

	var resolved []ast.Statement
	// Find "FASTLY [macro]" comment and extract in infix comment of block statement
	if hasFastlyBoilerplateMacro(sub.Block.Infix, macroName) {
		for _, s := range snippets {
			statements, err := loadStatementVCL(s.Name, s.Data)
			if err != nil {
				return errors.WithStack(err)
			}
			resolved = append(resolved, statements...)
		}
		// Prevent to block statements
		sub.Block.Statements = append(resolved, sub.Block.Statements...)
		return nil
	}

	// Find "FASTLY [macro]" comment and extract inside block statement
	var found bool // guard flag, embedding macro should do only once
	for _, stmt := range sub.Block.Statements {
		if hasFastlyBoilerplateMacro(stmt.GetMeta().Leading, macroName) && !found {
			for _, s := range snippets {
				statements, err := loadStatementVCL(s.Name, s.Data)
				if err != nil {
					return errors.WithStack(err)
				}
				resolved = append(resolved, statements...)
			}
			found = true // guard for only once
		}
		resolved = append(resolved, stmt) // don't forget to append original statement
	}
	sub.Block.Statements = resolved
	return nil
}

func hasFastlyBoilerplateMacro(cs ast.Comments, macroName string) bool {
	for _, c := range cs {
		line := strings.TrimLeft(c.String(), " */#")
		if strings.HasPrefix(strings.ToUpper(line), macroName) {
			return true
		}
	}
	return false
}

// validateAndSetParameters validates argument count and types against subroutine parameters,
// performs implicit type conversion if needed, and sets them as local variables.
func (i *Interpreter) validateAndSetParameters(sub *ast.SubroutineDeclaration, args []value.Value) error {
	// Check argument count matches parameter count
	if len(args) != len(sub.Parameters) {
		return exception.Runtime(
			&sub.GetMeta().Token,
			"Subroutine %s expects %d arguments, but got %d",
			sub.Name.Value,
			len(sub.Parameters),
			len(args),
		)
	}

	// Validate and set each parameter
	for idx, param := range sub.Parameters {
		arg := args[idx]
		converted, err := convertValueToType(arg, value.Type(param.Type.Value))
		if err != nil {
			return exception.Runtime(
				&param.GetMeta().Token,
				"Invalid parameter %s, expects=%s, but got=%s. Conversion failed: %s",
				param.Name.Value,
				param.Type.Value,
				arg.Type(),
				err.Error(),
			)
		}
		i.localVars[param.Name.Value] = converted
	}

	return nil
}

// convertValueToType attempts to convert a value to the expected type using implicit
// conversion rules.
// Under the hood it delegates actual conversion to assign.Assign function but on top of it,
// it enforces additional restrictions specific to function arguments and return values.
func convertValueToType(val value.Value, expectedType value.Type) (value.Value, error) {
	// shortcut for values that do not require conversion.
	// literals do require reassignment to prevent IsLiteral flag from
	// propagating into the function argument or return value.
	// Because of that they are still delegated to Assign function.
	if val.Type() == expectedType && !val.IsLiteral() {
		return val, nil
	}
	// additional restrictions specific to function calls
	// on top of what is already enforced by Assign function
	switch expectedType {
	case value.IntegerType:
		switch val.Type() {
		case value.FloatType, value.RTimeType, value.TimeType:
			return nil, fmt.Errorf("expected an INTEGER variable")
		}
	case value.FloatType:
		switch val.Type() {
		case value.RTimeType, value.TimeType:
			return nil, fmt.Errorf("expected a FLOAT or INTEGER variable")
		}
	case value.RTimeType:
		switch val.Type() {
		case value.IntegerType, value.FloatType, value.TimeType:
			return nil, fmt.Errorf("expected an RTIME variable")
		}
	case value.TimeType:
		switch val.Type() {
		case value.IntegerType, value.FloatType, value.RTimeType:
			return nil, fmt.Errorf("expected a TIME variable")
		}
	case value.IpType:
		if !val.IsLiteral() && val.Type() == value.StringType {
			return nil, fmt.Errorf("expected an IP variable")
		}
	}
	if result, err := value.Create(expectedType); err != nil {
		return nil, err
	} else if err := assign.Assign(result, val); err != nil {
		return nil, err
	} else {
		return result, nil
	}
}
