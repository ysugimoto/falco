package context

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/snippets"
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

func ScopesString(s int) string {
	var sb strings.Builder
	for i := RECV; i != LOG; i <<= 4 {
		scope := ScopeString(s & i)
		if scope != "UNKNOWN" {
			sb.WriteString(scope)
			sb.WriteString(" ")
		}
	}
	return sb.String()
}

func CanAccessVariableInScope(objScope int, objReference, name string, currentScope int) error {
	// objScope: is a bitmap of all the scopes that the variable is available in e.g. 0x100000001 is only available in RECV and LOG
	// currentScope: is the bitmap of the current scope. In VCL state functions such as vcl_recv only one bit will be set.
	// however in subroutines or user defined functions things are different, since a subroutine might be used in multiple function.
	// We calculate if objScope & currentScope (the common scopes) is the same as the current scope
	if (objScope & currentScope) != currentScope {
		missingScopes := (objScope & currentScope) ^ currentScope
		message := fmt.Sprintf(`Variable "%s" could not access in scope of %s`, name, ScopesString(missingScopes))
		if objReference != "" {
			message += "\nSee reference documentation: " + objReference
		}
		return fmt.Errorf(message)
	}
	return nil
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
	Get        types.Type
	Set        types.Type
	Unset      bool
	Scopes     int
	Reference  string
	Deprecated bool
}

type Context struct {
	// private fields
	curMode        int
	prevMode       int
	curName        string
	functions      Functions
	Variables      Variables
	resolver       resolver.Resolver
	fastlySnippets *snippets.Snippets

	// public fields
	Acls              map[string]*types.Acl
	Backends          map[string]*types.Backend
	Tables            map[string]*types.Table
	Directors         map[string]*types.Director
	Subroutines       map[string]*types.Subroutine
	Penaltyboxes      map[string]*types.Penaltybox
	Ratecounters      map[string]*types.Ratecounter
	Gotos             map[string]*types.Goto
	GotoDestinations  map[string]struct{}
	Identifiers       map[string]struct{}
	RegexVariables    map[string]int
	ReturnType        *types.Type
	CurrentSubroutine *ast.SubroutineDeclaration
}

func New(opts ...Option) *Context {
	c := &Context{
		curMode:          RECV,
		curName:          "vcl_recv",
		Acls:             make(map[string]*types.Acl),
		Backends:         make(map[string]*types.Backend),
		Tables:           make(map[string]*types.Table),
		Directors:        make(map[string]*types.Director),
		Subroutines:      make(map[string]*types.Subroutine),
		Penaltyboxes:     make(map[string]*types.Penaltybox),
		Ratecounters:     make(map[string]*types.Ratecounter),
		Gotos:            make(map[string]*types.Goto),
		GotoDestinations: make(map[string]struct{}),
		Identifiers:      builtinIdentifiers(),
		functions:        builtinFunctions(),
		Variables:        predefinedVariables(),
		RegexVariables:   newRegexMatchedValues(),
	}

	for i := range opts {
		opts[i](c)
	}
	return c
}

func (c *Context) Mode() int {
	return c.curMode
}

// Returns true if statement/expression is inside state-mechine subroutine like "vcl_recv", fastly reserved one
func (c *Context) IsStateMachineMethod() bool {
	if c.CurrentSubroutine == nil {
		return false
	}
	return IsFastlySubroutine(c.CurrentSubroutine.Name.Value)
}

func (c *Context) Resolver() resolver.Resolver {
	if c.resolver == nil {
		c.resolver = &resolver.EmptyResolver{}
	}
	return c.resolver
}

func (c *Context) Snippets() *snippets.Snippets {
	if c.fastlySnippets == nil {
		c.fastlySnippets = &snippets.Snippets{}
	}
	return c.fastlySnippets
}

func (c *Context) CurrentFunction() string {
	return c.curName
}

func (c *Context) Restore() *Context {
	c.curMode = c.prevMode
	c.prevMode = 0

	// clear local variables
	delete(c.Variables, "var")
	// clear local goto definitions
	c.Gotos = make(map[string]*types.Goto)

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
//
//	if (req.http.Host) {
//		if (var.S) {
//			if (var.S !~ "(foo)\s(bar)\s(baz)") { // make matched values first (1)
//				set req.http.First = "1";
//			}
//			set var.S = "hoge huga";
//			if (var.S ~ "(hoge)\s(huga)") { // override matched values (2)
//				set req.http.First = re.group.1;
//			}
//		}
//		set req.http.Third = re.group.2; // difficult to know which (1) or (2) matched result is used
//	}
//
//	if (req.http.Host) {
//		set req.http.Fourth = re.group.3; // difficult to know which (1) or (2) matched result is used or empty
//	}
//
// ```
//
// Therefore we will raise warning if matched value is overridden in subroutine.
func (c *Context) PushRegexVariables(matchN int) error {
	for i := 0; i < matchN; i++ {
		c.RegexVariables[fmt.Sprintf("re.group.%d", i)]++
	}

	// If pushed count is greater than 1, variable is overridden in the subroutine statement
	if c.RegexVariables["re.group.0"] > 1 {
		return fmt.Errorf("Regex captured variable may override older one")
	}
	return nil
}

// Get regex group variable
func (c *Context) GetRegexGroupVariable(name string) (types.Type, error) {
	if _, ok := c.RegexVariables[name]; !ok {
		return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
	}
	// group matched value is always STRING
	return types.StringType, nil
}

// Get ratecounter variable
func (c *Context) GetRatecounterVariable(name string) (types.Type, error) {
	// Ratecounter variables have the shape: ratecounter.{Variable Name}.[bucket/rate].Time
	nameComponents := strings.Split(name, ".")
	if len(nameComponents) != 4 {
		return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
	}

	ratecounterVariableName := nameComponents[1]
	// Check first if this ratecounter is defined in the first place.
	if _, ok := c.Ratecounters[ratecounterVariableName]; !ok {
		return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
	}

	// nameComponents[0] should be "ratecounter"
	// nameComponents[1] should be the variable name
	// nameComponents[2] should be either "bucket" or "rate"
	// nameComponents[3] should be the time (10s, 60s, etc)
	if v, ok := c.Variables[nameComponents[0]].Items["%any%"].Items[nameComponents[2]].Items[nameComponents[3]]; ok {
		return v.Value.Get, nil
	}

	return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
}

func (c *Context) AddAcl(name string, acl *types.Acl) error {
	// check existence
	if _, duplicated := c.Acls[name]; duplicated {
		return fmt.Errorf(`Duplicate definition of ACL "%s"`, name)
	}
	c.Acls[name] = acl
	return nil
}

func (c *Context) AddBackend(name string, backend *types.Backend) error {
	// check existence
	if _, duplicated := c.Backends[name]; duplicated {
		return fmt.Errorf(`Duplicate definition of backend "%s"`, name)
	}
	c.Backends[name] = backend

	// Additionally, assign some backend name related predefined variable
	c.Variables["backend"].Items[name] = dynamicBackend()

	return nil
}

func (c *Context) AddTable(name string, table *types.Table) error {
	// check existence
	if _, duplicated := c.Tables[name]; duplicated {
		return fmt.Errorf(`Duplicate definition of table "%s"`, name)
	}
	c.Tables[name] = table
	return nil
}

func (c *Context) AddDirector(name string, director *types.Director) error {
	// check existence
	if _, duplicated := c.Directors[name]; duplicated {
		return fmt.Errorf(`Duplicate definition of director "%s"`, name)
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

	// And, director target backend identifiers should be marked as used
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
			return fmt.Errorf(`Duplicate definition of subroutine "%s"`, name)
		}
	}

	if _, duplicated := c.Subroutines[name]; duplicated {
		if !IsFastlySubroutine(name) {
			return fmt.Errorf(`Duplicate definition of subroutine "%s"`, name)
		}
	}

	c.Subroutines[name] = subroutine
	return nil
}

func (c *Context) AddUserDefinedFunction(name string, scopes int, returnType types.Type) error {
	// check existence
	if _, duplicated := c.functions[name]; duplicated {
		if !IsFastlySubroutine(name) {
			return fmt.Errorf(`Duplicate definition of subroutine "%s"`, name)
		}
	}

	if _, duplicated := c.Subroutines[name]; duplicated {
		if !IsFastlySubroutine(name) {
			return fmt.Errorf(`Duplicate definition of subroutine "%s"`, name)
		}
	}

	c.functions[name] = &FunctionSpec{
		Items: map[string]*FunctionSpec{},
		Value: &BuiltinFunction{
			Return:                returnType,
			Arguments:             [][]types.Type{},
			Scopes:                scopes,
			IsUserDefinedFunction: true,
		},
	}

	return nil
}

func (c *Context) AddPenaltybox(name string, penaltybox *types.Penaltybox) error {
	// check existence
	if _, duplicated := c.Penaltyboxes[name]; duplicated {
		return fmt.Errorf(`Duplicate definition of penaltybox "%s"`, name)
	} else {
		c.Penaltyboxes[name] = penaltybox
	}
	return nil
}

func (c *Context) AddRatecounter(name string, ratecounter *types.Ratecounter) error {
	// check existence
	if _, duplicated := c.Ratecounters[name]; duplicated {
		return fmt.Errorf(`Duplicate definition of ratecounter "%s"`, name)
	} else {
		c.Ratecounters[name] = ratecounter
	}
	return nil
}

func (c *Context) AddGoto(name string, newGoto *types.Goto) error {
	// append colon to the goto name to be able to identify it when it is been used.
	name += ":"

	// check existence
	if _, duplicated := c.Gotos[name]; duplicated {
		return fmt.Errorf(`Duplicate definition of goto "%s"`, name)
	} else {
		c.Gotos[name] = newGoto
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

	// If program want to access to ratecounter variables like "ratecounter.{Name}.bucket.10s",
	// proxy to dedicated getter.
	if first == "ratecounter" {
		return c.GetRatecounterVariable(name)
	}

	obj, ok := c.Variables[first]
	if !ok {
		return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
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
				return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
			}
		} else {
			obj = v
		}
	}

	// Check object existence
	if obj == nil || obj.Value == nil {
		return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
	}
	// Value exists, but unable to access in current scope
	if err := CanAccessVariableInScope(obj.Value.Scopes, obj.Value.Reference, name, c.curMode); err != nil {
		return types.NullType, err
	}

	// Unable "Get" access
	if obj.Value.Get == types.NeverType {
		message := fmt.Sprintf(`Variable "%s" could not read`, name)
		if obj.Value.Reference != "" {
			message += "\nSee reference documentation: " + obj.Value.Reference
		}
		return types.NullType, fmt.Errorf(message)
	}

	// Mark as accessed
	obj.IsUsed = true

	// Check deprecation
	if obj.Value.Deprecated {
		return obj.Value.Get, ErrDeprecated
	}

	return obj.Value.Get, nil
}

func (c *Context) Set(name string) (types.Type, error) {
	first, remains := splitName(name)

	// regex group variable like "re.group.N" is known read-only,
	if first == "re" {
		return types.NullType, fmt.Errorf(`Variable "%s" is read-only`, name)
	}

	obj, ok := c.Variables[first]
	if !ok {
		return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
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
				return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
			}
		} else {
			obj = v
		}
	}

	// Check object existence
	if obj == nil || obj.Value == nil {
		return types.NullType, fmt.Errorf(`Undefined variable "%s"`, name)
	}

	// Value exists, but unable to access in current scope
	if err := CanAccessVariableInScope(obj.Value.Scopes, obj.Value.Reference, name, c.curMode); err != nil {
		return types.NullType, err
	}

	// Unable "Set" access, means read-only.
	if obj.Value.Set == types.NeverType {
		message := fmt.Sprintf(`Variable "%s" is read-only`, name)
		if obj.Value.Reference != "" {
			message += "\nSee reference documentation: " + obj.Value.Reference
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
		return fmt.Errorf(`Variable "%s" is already declared`, name)
	}

	first, remains := splitName(name)

	// declaration syntax for variables is:
	// declare local var.variableName [type]
	// which means that they must be prefixed with var.
	if first != "var" {
		return fmt.Errorf(`Variable "%s" declaration error: Variable must be prefixed with 'var.'`, name)
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
		return fmt.Errorf(`Variable "%s" is read-only`, name)
	}

	obj, ok := c.Variables[first]
	if !ok {
		return fmt.Errorf(`Undefined variable "%s"`, name)
	}

	for _, key := range remains {
		if v, ok := obj.Items[key]; !ok {
			if v, ok := obj.Items["%any%"]; ok {
				obj = &Object{
					Items: map[string]*Object{},
					Value: v.Value,
				}
			} else {
				return fmt.Errorf(`Undefined variable "%s"`, name)
			}
		} else {
			obj = v
		}
	}

	// Check object existence
	if obj == nil || obj.Value == nil {
		return nil
	}
	// Value exists, but unable to access in current scope
	if err := CanAccessVariableInScope(obj.Value.Scopes, obj.Value.Reference, name, c.curMode); err != nil {
		return err
	}
	// Unable "Unset" access, means could not unset.
	if !obj.Value.Unset {
		message := fmt.Sprintf(`Variable "%s" is read-only`, name)
		if obj.Value.Reference != "" {
			message += "\nSee reference documentation: " + obj.Value.Reference
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
		return nil, fmt.Errorf(`Function "%s" is not defined`, name)
	}

	for _, key := range remains {
		if v, ok := obj.Items[key]; !ok {
			return nil, fmt.Errorf(`Function "%s" is not defined`, name)
		} else {
			obj = v
		}
	}

	// Check object existence
	if obj == nil || obj.Value == nil {
		return nil, fmt.Errorf(`"%s" is not a function`, name)
	}
	// Value exists, but unable to access in current scope
	if obj.Value.Scopes&c.curMode == 0 {
		return nil, fmt.Errorf(
			`Function "%s" is not available in scope %s\nSee reference documentation: %s`,
			name, ScopeString(c.curMode), obj.Value.Reference,
		)
	}

	return obj.Value, nil
}

func splitName(name string) (string, []string) {
	var first string
	var remains []string

	sep := strings.SplitN(name, ".", 4)
	first = sep[0]
	if len(sep) == 1 {
		return first, remains
	}

	// Consider to object access like req.http.Cookie:cookie-name
	// Cookie may has dot, so we need to concat remains after ":" token as object name
	for i, v := range sep[1:] {
		if strings.Contains(v, ":") {
			remains = append(remains, strings.Join(sep[i+1:], "."))
			break
		} else {
			remains = append(remains, v)
		}
	}

	return first, remains
}
