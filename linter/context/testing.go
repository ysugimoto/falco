package context

import (
	"maps"

	"github.com/ysugimoto/falco/v2/linter/types"
)

// TestingCallSubroutineName is the fully-qualified name used in VCL test files.
const TestingCallSubroutineName = "testing.call_subroutine"

// testingFunctions returns BuiltinFunction specs for the "testing.*" namespace.
// These specs are registered unconditionally so that GetFunction resolves
// "testing.call_subroutine" without an "undefined function" error.
//
// The Arguments list is left nil here because the variadic extra arguments
// (forwarded to the target subroutine) are validated via special-case logic
// in lintFunctionCallStatement rather than through lintFunctionArguments.
func testingFunctions() Functions {
	allScopes := RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG | PIPE
	return Functions{
		"testing": &FunctionSpec{
			Items: map[string]*FunctionSpec{
				"call_subroutine": {
					Items: map[string]*FunctionSpec{},
					Value: &BuiltinFunction{
						// nil Arguments — standard lintFunctionArguments is
						// bypassed; see lintFunctionCallStatement special case.
						Arguments: nil,
						Return:    types.NeverType,
						Scopes:    allScopes,
					},
				},
			},
		},
	}
}

// registerTestingFunctions merges the testing function specs into c.functions.
func registerTestingFunctions(c *Context) {
	maps.Copy(c.functions, testingFunctions())
}
