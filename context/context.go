package context

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/types"
)

const (
	INIT    int = 0x000000000
	RECV    int = 0x000000001
	HASH    int = 0x000000010
	HIT     int = 0x000000100
	MISS    int = 0x000001000
	PASS    int = 0x000010000
	FETCH   int = 0x000100000
	ERROR   int = 0x001000000
	DELIVER int = 0x010000000
	LOG     int = 0x100000000
)

func ScopeString(s int) string {
	switch s {
	case RECV:
		return "RECV"
	case HASH:
		return "HASH"
	case HIT:
		return "HIT"
	case MISS:
		return "MISS"
	case PASS:
		return "PASS"
	case FETCH:
		return "FETCH"
	case ERROR:
		return "ERROR"
	case DELIVER:
		return "DELIVER"
	case LOG:
		return "LOG"
	default:
		return "UNKNOWN"
	}
}

var fastlyReservedSubroutines = map[string]bool{
	"vcl_recv":    true,
	"vcl_hash":    true,
	"vcl_hit":     true,
	"vcl_miss":    true,
	"vcl_pass":    true,
	"vcl_fetch":   true,
	"vcl_error":   true,
	"vcl_deliver": true,
	"vcl_log":     true,
}

func IsFastlySubroutine(name string) bool {
	return fastlyReservedSubroutines[name]
}

type Variables map[string]*Object

type Object struct {
	Items  map[string]*Object
	Value  *Accessor
	IsUsed bool
	Meta   *ast.Meta
}

type Accessor struct {
	Get       types.Type
	Set       types.Type
	Unset     bool
	Scopes    int
	Reference string
}

type Context struct {
	curMode        int
	prevMode       int
	curName        string
	Acls           map[string]*types.Acl
	Backends       map[string]*types.Backend
	Tables         map[string]*types.Table
	Directors      map[string]*types.Director
	Subroutines    map[string]*types.Subroutine
	Identifiers    map[string]struct{}
	functions      Functions
	Variables      Variables
	RegexVariables map[string]int
	ReturnType     *types.Type
}

func New() *Context {
	return &Context{
		curMode:        RECV,
		curName:        "vcl_recv",
		Acls:           make(map[string]*types.Acl),
		Backends:       make(map[string]*types.Backend),
		Tables:         make(map[string]*types.Table),
		Directors:      make(map[string]*types.Director),
		Subroutines:    make(map[string]*types.Subroutine),
		Identifiers:    builtinIdentifiers(),
		functions:      builtinFunctions(),
		Variables:      predefinedVariables(),
		RegexVariables: newRegexMatchedValues(),
	}
}

func (c *Context) Mode() int {
	return c.curMode
}

func (c *Context) CurrentFunction() string {
	return c.curName
}

func (c *Context) Restore() *Context {
	c.curMode = c.prevMode
	c.prevMode = 0

	// clear local variables
	delete(c.Variables, "var")

	return c
}

func (c *Context) Scope(mode int) *Context {
	c.prevMode = c.curMode
	c.curMode = mode
	// reset regex matched value
	c.RegexVariables = newRegexMatchedValues()
	return c
}

func (c *Context) UserDefinedFunctionScope(name string, mode int, returnType types.Type) *Context {
	c.prevMode = c.curMode
	c.curMode = mode
	// reset regex matched value
	c.RegexVariables = newRegexMatchedValues()
	c.ReturnType = &returnType
	c.curName = name
	return c
}

// Regex variables, "re.group.N" is a special variable in VCL.
// These variables could use if(else) block statement when condition has regex operator like "~" or "!~".
// Note that group matched variable has potential of making bugs due to its spec:
// 1. re.group.N variable scope is subroutine-global, does not have block scope
// 2. matched value may override on second regex matching
//
// For example:
//
// ```
// declare local var.S STRING;
// set var.S = "foo bar baz";
// if (req.http.Host) {
// 	if (var.S) {
// 		if (var.S !~ "(foo)\s(bar)\s(baz)") { // make matched values first (1)
// 			set req.http.First = "1";
// 		}
// 		set var.S = "hoge huga";
// 		if (var.S ~ "(hoge)\s(huga)") { // override matched values (2)
// 			set req.http.First = re.group.1;
// 		}
// 	}
// 	set req.http.Third = re.group.2; // difficult to know which (1) or (2) matched result is used
// }
//
// if (req.http.Host) {
// 	set req.http.Fourth = re.group.3; // difficult to know which (1) or (2) matched result is used or empty
// }
// ```
//
// Therefore we will raise warning if matched value is overridden in subroutine.
func (c *Context) PushRegexVariables(matchN int) error {
	for i := 0; i < matchN; i++ {
		c.RegexVariables[fmt.Sprintf("re.group.%d", i)]++
	}

	// If pushed count is greater than 1, variable is overridden in the subroutine statement
	if c.RegexVariables["re.group.0"] > 1 {
		return fmt.Errorf("Regex captured variable may override older one.")
	}
	return nil
}

// Get regex group variable
func (c *Context) GetRegexGroupVariable(name string) (types.Type, error) {
	if _, ok := c.RegexVariables[name]; !ok {
		return types.NullType, fmt.Errorf(`undefined variable "%s"`, name)
	}
	// group matched value is always STRING
	return types.StringType, nil
}

func (c *Context) AddAcl(name string, acl *types.Acl) error {
	// check existence
	if _, duplicated := c.Acls[name]; duplicated {
		return fmt.Errorf(`duplicate deifnition of acl "%s"`, name)
	}
	c.Acls[name] = acl
	return nil
}

func (c *Context) AddBackend(name string, backend *types.Backend) error {
	// check existence
	if _, duplicated := c.Backends[name]; duplicated {
		return fmt.Errorf(`duplicate deifnition of backend "%s"`, name)
	}
	c.Backends[name] = backend

	// Additionally, assign some backend name related predefiend variable
	c.Variables["backend"].Items[name] = dynamicBackend()
	c.Variables["ratecounter"] = &Object{
		Items: map[string]*Object{
			name: dynamicRateCounter(),
		},
	}

	return nil
}

func (c *Context) AddTable(name string, table *types.Table) error {
	// check existence
	if _, duplicated := c.Tables[name]; duplicated {
		return fmt.Errorf(`duplicate deifnition of table "%s"`, name)
	}
	c.Tables[name] = table
	return nil
}

func (c *Context) AddDirector(name string, director *types.Director) error {
	// check existence
	if _, duplicated := c.Directors[name]; duplicated {
		return fmt.Errorf(`duplicate deifnition of director "%s"`, name)
	}
	c.Directors[name] = director

	// Director also need to add backend due to director can set as backend in VCL.
	c.Backends[name] = &types.Backend{
		DirectorDecl: director.Decl,
	}

	c.Variables["director"] = &Object{
		Items: map[string]*Object{
			name: dynamicDirector(),
		},
	}

	// And, director target backend identifilers should be marked as used
	for _, d := range director.Decl.Properties {
		bo, ok := d.(*ast.DirectorBackendObject)
		if !ok {
			continue
		}
		for _, v := range bo.Values {
			if v.Key.Value != "backend" {
				continue
			}
			if ident, ok := v.Value.(*ast.Ident); ok {
				if b, ok := c.Backends[ident.Value]; ok {
					b.IsUsed = true
				}
			}
		}
	}

	return nil
}

func (c *Context) AddSubroutine(name string, subroutine *types.Subroutine) error {
	// check existence
	if _, duplicated := c.functions[name]; duplicated {
		if !IsFastlySubroutine(name) {
			return fmt.Errorf(`duplication definition of subroutine "%s"`, name)
		}
	}

	if _, duplicated := c.Subroutines[name]; duplicated {
		if !IsFastlySubroutine(name) {
			return fmt.Errorf(`duplication definition of subroutine "%s"`, name)
		}
	}

	c.Subroutines[name] = subroutine
	return nil
}

func (c *Context) AddUserDefinedFunction(name string, scopes int, returnType types.Type) error {
	// check existence
	if _, duplicated := c.functions[name]; duplicated {
		if !IsFastlySubroutine(name) {
			return fmt.Errorf(`duplication definition of subroutine "%s"`, name)
		}
	}

	if _, duplicated := c.Subroutines[name]; duplicated {
		if !IsFastlySubroutine(name) {
			return fmt.Errorf(`duplication definition of subroutine "%s"`, name)
		}
	}

	c.functions[name] = &FunctionSpec{
		Items: map[string]*FunctionSpec{},
		Value: &BuiltinFunction{
			Return:    returnType,
			Arguments: [][]types.Type{},
			Scopes:    scopes,
		},
	}

	return nil
}

func (c *Context) Get(name string) (types.Type, error) {
	first, remains := splitName(name)

	// If program want to access to regex group like "re.group.N",
	// proxy to dedicated getter.
	if first == "re" {
		return c.GetRegexGroupVariable(name)
	}

	obj, ok := c.Variables[first]
	if !ok {
		return types.NullType, fmt.Errorf(`undefined variable "%s"`, name)
	}

	for _, key := range remains {
		if v, ok := obj.Items[key]; !ok {
			// Special case, VCL allows to Set/Get/Unset for {NAME} of any key name.
			// If program would set to this property, we enables to assign with its types (may string type).
			if v, ok := obj.Items["%any%"]; ok {
				key = strings.ToLower(key)
				obj.Items[key] = &Object{
					Items: map[string]*Object{},
					Value: v.Value,
				}
				obj = obj.Items[key]
			} else {
				return types.NullType, fmt.Errorf(`undefined variable "%s"`, name)
			}
		} else {
			obj = v
		}
	}

	// Check object existence
	if obj == nil || obj.Value == nil {
		return types.NullType, fmt.Errorf(`undefined variable "%s"`, name)
	}
	// Value exists, but uneable to access in current scope
	if obj.Value.Scopes&c.curMode == 0 {
		message := fmt.Sprintf(`variable "%s" could not access in scope of %s`, name, ScopeString(c.curMode))
		if obj.Value.Reference != "" {
			message += "\ndocument: " + obj.Value.Reference
		}
		return types.NullType, fmt.Errorf(message)
	}
	// Unable "Get" access
	if obj.Value.Get == types.NeverType {
		message := fmt.Sprintf(`variable "%s" could not read`, name)
		if obj.Value.Reference != "" {
			message += "\ndocument: " + obj.Value.Reference
		}
		return types.NullType, fmt.Errorf(message)
	}

	// Mark as accessed
	obj.IsUsed = true

	return obj.Value.Get, nil
}

func (c *Context) Set(name string) (types.Type, error) {
	first, remains := splitName(name)

	// regex group variable like "re.group.N" is known read-only,
	if first == "re" {
		return types.NullType, fmt.Errorf(`variable "%s" is read-only`, name)
	}

	obj, ok := c.Variables[first]
	if !ok {
		return types.NullType, fmt.Errorf(`undefined variable "%s"`, name)
	}

	for _, key := range remains {
		if v, ok := obj.Items[key]; !ok {
			// Special case, VCL allows to Set/Get/Unset for {NAME} of any key name.
			// If program set to this property, we enables to assign with its types (may string type).
			// And, almost name indicates HTTP header so case insensitive.
			if v, ok := obj.Items["%any%"]; ok {
				key = strings.ToLower(key)
				obj.Items[key] = &Object{
					Items: map[string]*Object{},
					Value: v.Value,
				}
				obj = obj.Items[key]
			} else {
				return types.NullType, fmt.Errorf(`undefined variable "%s"`, name)
			}
		} else {
			obj = v
		}
	}

	// Check object existence
	if obj == nil || obj.Value == nil {
		return types.NullType, fmt.Errorf(`undefined variable "%s"`, name)
	}
	// Value exists, but uneable to access in current scope
	if obj.Value.Scopes&c.curMode == 0 {
		message := fmt.Sprintf(`variable "%s" could not access in scope of %s`, name, ScopeString(c.curMode))
		if obj.Value.Reference != "" {
			message += "\ndocument: " + obj.Value.Reference
		}
		return types.NullType, fmt.Errorf(message)
	}
	// Unable "Set" access, means read-only.
	if obj.Value.Set == types.NeverType {
		message := fmt.Sprintf(`variable "%s" is read-only`, name)
		if obj.Value.Reference != "" {
			message += "\ndocument: " + obj.Value.Reference
		}
		return types.NullType, fmt.Errorf(message)
	}

	// Mark as accessed
	obj.IsUsed = true

	return obj.Value.Set, nil
}

func (c *Context) Declare(name string, valueType types.Type, m *ast.Meta) error {
	if _, err := c.Get(name); err == nil {
		// If error is nil, variable already defined
		return fmt.Errorf(`variable "%s" is already declared`, name)
	}

	first, remains := splitName(name)

	// declaration syntax for variables is:
	// declare local var.variableName [type]
	// which means that they must be prefixed with var.
	if first != "var" {
		return fmt.Errorf(`variable "%s" declaration error. Variable be prefixed with 'var.'`, name)
	}

	obj, ok := c.Variables[first]
	if !ok {
		// Newly assign object
		obj = &Object{
			Items: map[string]*Object{},
		}
		c.Variables[first] = obj
	}

	for _, key := range remains {
		if v, ok := obj.Items[key]; !ok {
			// Newly assign object
			obj.Items[key] = &Object{
				Items: map[string]*Object{},
				Meta:  m,
			}
			obj = obj.Items[key]
		} else {
			obj = v
		}
	}

	obj.Value = &Accessor{
		Get:    valueType,
		Set:    valueType,
		Unset:  false,
		Scopes: c.curMode,
	}

	return nil
}

func (c *Context) Unset(name string) error {
	first, remains := splitName(name)

	// regex group variable like "re.group.N" is known read-only,
	if first == "re" {
		return fmt.Errorf(`variable "%s" is read-only`, name)
	}

	obj, ok := c.Variables[first]
	if !ok {
		return fmt.Errorf(`undefined variable "%s"`, name)
	}

	for _, key := range remains {
		if v, ok := obj.Items[key]; !ok {
			if v, ok := obj.Items["%any%"]; ok {
				obj = &Object{
					Items: map[string]*Object{},
					Value: v.Value,
				}
			} else {
				return fmt.Errorf(`undefined variable "%s"`, name)
			}
		} else {
			obj = v
		}
	}

	// Check object existence
	if obj == nil || obj.Value == nil {
		return nil
	}
	// Value exists, but uneable to access in current scope
	if obj.Value.Scopes&c.curMode == 0 {
		message := fmt.Sprintf(`variable "%s" could not access in scope of %s`, name, ScopeString(c.curMode))
		if obj.Value.Reference != "" {
			message += "\ndocument: " + obj.Value.Reference
		}
		return fmt.Errorf(message)
	}
	// Unable "Unset" access, means could not unset.
	if !obj.Value.Unset {
		message := fmt.Sprintf(`variable "%s" is read-only`, name)
		if obj.Value.Reference != "" {
			message += "\ndocument: " + obj.Value.Reference
		}
		return fmt.Errorf(message)
	}

	// Mark as accessed
	obj.IsUsed = true

	return nil
}

func (c *Context) GetFunction(name string) (*BuiltinFunction, error) {
	first, remains := splitName(name)

	obj, ok := c.functions[first]
	if !ok {
		fmt.Printf("Function %s is not defined \n", first)
		return nil, fmt.Errorf(`Function "%s" is not defined 1`, name)
	}

	for _, key := range remains {
		if v, ok := obj.Items[key]; !ok {
			return nil, fmt.Errorf(`Function "%s" is not defined 2`, name)
		} else {
			obj = v
		}
	}

	// Check object existence
	if obj == nil || obj.Value == nil {
		return nil, fmt.Errorf(`"%s" is not a function`, name)
	}
	// Value exists, but uneable to access in current scope
	if obj.Value.Scopes&c.curMode == 0 {
		return nil, fmt.Errorf(
			`function "%s" could not call in scope of %s\ndocument: %s`,
			name, ScopeString(c.curMode), obj.Value.Reference,
		)
	}

	return obj.Value, nil
}

func splitName(name string) (string, []string) {
	var first string
	var remains []string

	sep := strings.SplitN(name, ".", 4)
	if len(sep) == 1 {
		first = sep[0]
	} else {
		first, remains = sep[0], sep[1:]
	}

	return first, remains
}
