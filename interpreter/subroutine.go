package interpreter

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/process"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
	"github.com/ysugimoto/falco/token"
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
			if val.Type() != expectedType {
				// Try to perform implicit conversion
				converted, err := i.convertValueToType(val, expectedType, &t.GetMeta().Token)
				if err != nil {
					return val, NONE, exception.Runtime(
						&t.GetMeta().Token,
						"Invalid return type, expects=%s, but got=%s",
						sub.ReturnType.Value,
						val.Type(),
					)
				}
				val = converted
			}
			return val, NONE, nil
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
		expectedType := value.Type(param.Type.Value)

		// Try to convert argument to expected type
		converted, err := i.convertValueToType(arg, expectedType, &param.GetMeta().Token)
		if err != nil {
			return exception.Runtime(
				&param.GetMeta().Token,
				"Parameter %s expects type %s, but got %s",
				param.Name.Value,
				param.Type.Value,
				arg.Type(),
			)
		}
		i.localVars[param.Name.Value] = converted
	}

	return nil
}

// convertValueToType attempts to convert a value to the expected type using implicit conversion rules
func (i *Interpreter) convertValueToType(val value.Value, expectedType value.Type, tk *token.Token) (value.Value, error) {
	// If types match, no conversion needed
	if val.Type() == expectedType {
		return val, nil
	}

	switch expectedType {
	case value.StringType:
		// Almost any type can be converted to STRING
		switch v := val.(type) {
		case *value.Integer:
			return &value.String{Value: fmt.Sprintf("%d", v.Value)}, nil
		case *value.Float:
			return &value.String{Value: fmt.Sprintf("%g", v.Value)}, nil
		case *value.Boolean:
			if v.Value {
				return &value.String{Value: "1"}, nil
			}
			return &value.String{Value: "0"}, nil
		case *value.IP:
			return &value.String{Value: v.Value.String()}, nil
		case *value.RTime:
			return &value.String{Value: fmt.Sprintf("%fs", v.Value.Seconds())}, nil
		}
	case value.IntegerType:
		switch v := val.(type) {
		case *value.Float:
			return &value.Integer{Value: int64(v.Value)}, nil
		case *value.Boolean:
			if v.Value {
				return &value.Integer{Value: 1}, nil
			}
			return &value.Integer{Value: 0}, nil
		}
	case value.FloatType:
		switch v := val.(type) {
		case *value.Integer:
			return &value.Float{Value: float64(v.Value)}, nil
		case *value.Boolean:
			if v.Value {
				return &value.Float{Value: 1.0}, nil
			}
			return &value.Float{Value: 0.0}, nil
		}
	case value.BooleanType:
		switch v := val.(type) {
		case *value.Integer:
			return &value.Boolean{Value: v.Value != 0}, nil
		case *value.Float:
			return &value.Boolean{Value: v.Value != 0}, nil
		case *value.String:
			return &value.Boolean{Value: v.Value != ""}, nil
		}
	case value.IpType:
		if v, ok := val.(*value.String); ok {
			ip := net.ParseIP(v.Value)
			if ip == nil {
				return nil, exception.Runtime(tk, "Invalid IP address: %s", v.Value)
			}
			return &value.IP{Value: ip}, nil
		}
	}

	// No conversion available
	return nil, exception.Runtime(tk, "Cannot convert %s to %s", val.Type(), expectedType)
}
