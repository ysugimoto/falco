package linter

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/linter/context"
	"github.com/ysugimoto/falco/linter/types"
)

// handlePCREComment skips a PCRE comment (?#...) and returns the new index.
func handlePCREComment(pattern string, i int) int {
	i += 3 // Skip (?#
	for i < len(pattern) && pattern[i] != ')' {
		if pattern[i] == '\\' {
			i++ // Skip escaped character
		}
		i++
	}
	return i + 1 // Skip the closing )
}

// handlePCREConditional skips a PCRE conditional (?(...)) and returns the new index.
func handlePCREConditional(pattern string, i int) int {
	i += 3 // Move past "(?("
	depth := 1
	for i < len(pattern) && depth > 0 {
		switch pattern[i] {
		case '\\':
			i++ // Skip escaped character
		case '(':
			depth++
		case ')':
			depth--
		}
		i++
	}
	return i - 1 // Back up one since we'll increment at the end of the outer loop
}

// isInlineModifierChar returns true if the character is a valid inline modifier character.
func isInlineModifierChar(ch byte) bool {
	return ch == 'i' || ch == 'm' || ch == 's' || ch == 'x' ||
		ch == 'U' || ch == 'X' || ch == 'J' || ch == '-'
}

// handlePCREInlineModifier checks if the pattern has inline modifiers and whether
// it forms a modified non-capturing group. Returns newIndex.
func handlePCREInlineModifier(pattern string, i int) int {
	// Scan ahead to see if there's a : which makes it a modified group
	j := i + 3
	for j < len(pattern) && isInlineModifierChar(pattern[j]) {
		j++
	}
	// Whether it's a modified non-capturing group (?i:...) or just an inline modifier (?i),
	// we skip it the same way
	return i + 1
}

// handlePCRESpecialConstruct processes special PCRE constructs starting with (?
// and returns (shouldContinue, shouldCount, newIndex).
func handlePCRESpecialConstruct(pattern string, i int) (bool, bool, int) {
	if i+2 >= len(pattern) {
		return false, false, i
	}

	nextCh := pattern[i+2]
	switch nextCh {
	case ':':
		// Non-capturing group (?:...)
		return true, false, i + 1
	case '=', '!':
		// Lookahead (?=...) or negative lookahead (?!...)
		return true, false, i + 1
	case '<':
		// Could be lookbehind (?<=...) or negative lookbehind (?<!...)
		if i+3 < len(pattern) && (pattern[i+3] == '=' || pattern[i+3] == '!') {
			return true, false, i + 1
		}
		// Could also be named group (?<name>...) - count it
		return true, true, i + 1
	case '>':
		// Atomic group (?>...)
		return true, false, i + 1
	case '#':
		// Comment (?#...) - skip until closing )
		newIdx := handlePCREComment(pattern, i)
		return true, false, newIdx
	case 'P':
		// Python-style named group (?P<name>...) or (?P=name)
		if i+3 < len(pattern) && pattern[i+3] == '<' {
			// Named capture group - count it
			return true, true, i + 1
		}
		// (?P=name) is a backreference, not a group
		return true, false, i + 1
	case '\'':
		// Perl-style named group (?'name'...)
		return true, true, i + 1
	case '(':
		// Conditional (?(...)) or (?(condition)yes|no)
		newIdx := handlePCREConditional(pattern, i)
		return true, false, newIdx
	case 'R', '&':
		// Subroutine call (?R), (?&name), etc.
		return true, false, i + 1
	}

	// Check for inline modifiers
	if isInlineModifierChar(nextCh) {
		newIdx := handlePCREInlineModifier(pattern, i)
		return true, false, newIdx
	}

	// Some other special construct we might not recognize
	// To be safe, don't count it as a capture group
	return true, false, i + 1
}

// skipCharClassStart advances the index past special characters at the start
// of a character class ([^...] or []...]).
func skipCharClassStart(pattern string, i int) int {
	// Check for negated character class [^...]
	if i < len(pattern) && pattern[i] == '^' {
		i++
	}
	// Check for ] at start of character class (it's literal)
	if i < len(pattern) && pattern[i] == ']' {
		i++
	}
	return i
}

// countPCRECaptureGroups counts the number of actual capture groups in a PCRE pattern.
// It correctly handles:
// - Non-capturing groups (?:...)
// - Lookaheads/lookbehinds (?=...), (?!...), (?<=...), (?<!...)
// - Atomic groups (?>...)
// - Comments (?#...)
// - Other special constructs that don't capture
// - Escaped parentheses \( and \)
// - Character classes [...]
// - Named groups (?P<name>...) - counts as capture but PCRE doesn't support these for Fastly
func countPCRECaptureGroups(pattern string) int {
	count := 0
	inCharClass := false
	escaped := false
	i := 0

	for i < len(pattern) {
		ch := pattern[i]

		// Handle escape sequences
		if escaped {
			escaped = false
			i++
			continue
		}

		if ch == '\\' {
			escaped = true
			i++
			continue
		}

		// Handle character classes
		if ch == '[' && !inCharClass {
			inCharClass = true
			i++
			i = skipCharClassStart(pattern, i)
			continue
		}

		if ch == ']' && inCharClass {
			inCharClass = false
			i++
			continue
		}

		// Inside character class, parentheses are literals
		if inCharClass {
			i++
			continue
		}

		// Check for opening parenthesis
		if ch == '(' {
			// Look ahead to see if it's a special construct
			if i+1 < len(pattern) && pattern[i+1] == '?' {
				shouldContinue, shouldCount, newIdx := handlePCRESpecialConstruct(pattern, i)
				if shouldCount {
					count++
				}
				if shouldContinue {
					i = newIdx
					continue
				}
			}
			// Regular capturing group
			count++
		}

		i++
	}

	return count
}

var BackendPropertyTypes = map[string]types.Type{
	"dynamic":                  types.BoolType,
	"share_key":                types.StringType,
	"host":                     types.StringType,
	"port":                     types.StringType,
	"ssl":                      types.BoolType,
	"ssl_cert_hostname":        types.StringType,
	"max_tls_version":          types.StringType,
	"min_tls_version":          types.StringType,
	"ssl_check_cert":           types.IDType,
	"ssl_sni_hostname":         types.StringType,
	"between_bytes_timeout":    types.RTimeType,
	"connect_timeout":          types.RTimeType,
	"first_byte_timeout":       types.RTimeType,
	"keepalive_time":           types.RTimeType,
	"max_connections":          types.IntegerType,
	"host_header":              types.StringType,
	"always_use_host_header":   types.BoolType,
	"bypass_local_route_table": types.BoolType,
	"prefer_ipv6":              types.BoolType,
}

var BackendProbePropertyTypes = map[string]types.Type{
	"dummy":             types.BoolType,
	"request":           types.StringType,
	"expected_response": types.IntegerType,
	"interval":          types.RTimeType,
	"timeout":           types.RTimeType,
	"window":            types.IntegerType,
	"initial":           types.IntegerType,
	"threshold":         types.IntegerType,
	"url":               types.StringType,
}

type DirectorProps struct {
	Rule     Rule
	Props    map[string]types.Type
	Requires []string
}

var DirectorPropertyTypes = map[string]DirectorProps{
	"random": {
		Rule: DIRECTOR_PROPS_RANDOM,
		Props: map[string]types.Type{
			"retries": types.IntegerType,
			"quorum":  types.IntegerType,
			"backend": types.BackendType,
			"weight":  types.IntegerType,
		},
		Requires: []string{"weight"},
	},
	"fallback": {
		Rule: DIRECTOR_PROPS_FALLBACK,
		Props: map[string]types.Type{
			"backend": types.BackendType,
		},
		Requires: []string{},
	},
	"hash": {
		Rule: DIRECTOR_PROPS_HASH,
		Props: map[string]types.Type{
			"quorum":  types.IntegerType,
			"backend": types.BackendType,
			"weight":  types.IntegerType,
		},
		Requires: []string{"weight"},
	},
	"client": {
		Rule: DIRECTOR_PROPS_CLIENT,
		Props: map[string]types.Type{
			"quorum":  types.IntegerType,
			"backend": types.BackendType,
			"weight":  types.IntegerType,
		},
		Requires: []string{"weight"},
	},
	"chash": {
		Rule: DIRECTOR_PROPS_CHASH,
		Props: map[string]types.Type{
			"key":             types.BackendType, // TODO: need accept object or client
			"seed":            types.IntegerType,
			"vnodes_per_node": types.IntegerType,
			"quorum":          types.IntegerType,
			"weight":          types.IntegerType,
			"id":              types.StringType,
			"backend":         types.BackendType,
		},
		Requires: []string{"id"},
	},
	"shield": {
		// We should do linting loughly because this type is only provided via Faslty Origin-Shielding
		Props: map[string]types.Type{
			"shield": types.StringType,
			"is_ssl": types.BoolType,
		},
		Requires: []string{"shield"},
	},
}

func isAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// isValidName validates ident name has only [0-9a-zA-Z_]+
func isValidName(name string) bool {
	for _, r := range name {
		if isAlphaNumeric(r) || r == '_' {
			continue
		}
		return false
	}
	return true
}

// isValidVariableName validates ident name has only [0-9a-zA-Z_\.-:]+
func isValidVariableName(name string) bool {
	for _, r := range name {
		if isAlphaNumeric(r) || r == '_' || r == '.' || r == '-' || r == ':' {
			continue
		}
		return false
	}
	return true
}

// isValidVariableNameWithWildcard validates ident name has only [0-9a-zA-Z_\.-:*]+ for unset/remove statement
func isValidVariableNameWithWildcard(name string) bool {
	asterisk := -1
	colon := -1
	dot := -1
	for index, r := range name {
		if isAlphaNumeric(r) || r == '_' || r == '.' || r == '-' || r == ':' || r == '*' {
			// Store the poisition of asterisk
			switch r {
			case '*':
				asterisk = index
			case ':':
				colon = index
			case '.':
				dot = index
			}
			continue
		}
		return false
	}

	// If asterisk character found, the poistion must be the end of name or must not be the after of colon.
	// unset req.http.*       // <- invalid
	// unset req.http.X-*Foo  // <- invalid
	// unset req.http.VARS:*  // <- invalid
	// unset req.http.X-*     // <- valid
	// unset req.http.VARS:V* // <- valid
	if asterisk != -1 {
		if colon != -1 && asterisk == colon+1 {
			return false
		}
		if asterisk == 0 || asterisk != len(name)-1 {
			return false
		}
		if dot != -1 && asterisk == dot+1 {
			return false
		}
	}
	return true
}

// In VCL, could not specify literal in if condition expression.
//
// if (!req.http.Cookie) { ... } // -> valid, inverse actual identity variable (implicit type conversion will occur)
// if (!false) { ... }           // -> valid, inverse boolean
// if (!10) { ... }              // -> invalid, could not use with integer literal
// if (!"example") { ... }       // -> invalid, could not use with string literal
//
// So we'd check validity following function.
func isValidConditionExpression(cond ast.Expression) error {
	switch t := cond.(type) {
	case *ast.PrefixExpression:
		return isValidConditionExpression(t.Right)
	case *ast.InfixExpression:
		return isValidConditionExpression(t.Left)
	default:
		if isLiteralExpression(cond) {
			return fmt.Errorf("could not specify literal in first expression")
		}
	}
	return nil
}

// In VCL, bang operator could not use in set/add statement expression,
// and only string concatenation expression could use.
//
// declare local var.Foo BOOL;
// declare local var.Bar STRING;
// set var.Bar = "foo" "bar";                         // -> valid, string concatenation operator can use
// set var.Foo = (req.http.Host == "example.com");    // -> valid, equal operator cau use inside grouped expression set statement
// set var.Bar = (req.http.Host == "example.com");    // -> invalid, expression must be an string
// set var.Foo = !false;                              // -> invalid, could not use in set statement
// set var.Bar = !tls.client.certificate.is_cert_bad; // -> invalid, expression must be an string
// set var.Foo = req.http.Host == "example.com";      // -> invalid, equal operator could not use in set statement
//
// So we'd check validity following function.
func isValidStatementExpression(leftType types.Type, exp ast.Expression) error {
	switch t := exp.(type) {
	case *ast.PrefixExpression:
		if t.Operator == "!" {
			return fmt.Errorf("could not specify bang operator in first expression")
		}
	case *ast.InfixExpression:
		if t.Operator != "+" {
			return fmt.Errorf("could not specify %s operator in statement", t.Operator)
		}
	case *ast.GroupedExpression:
		if leftType != types.BoolType {
			return fmt.Errorf("could not specify grouped expression excepting boolean statement")
		}
	}
	return nil
}

func isValidReturnExpression(exp ast.Expression) error {
	switch t := exp.(type) {
	case *ast.PrefixExpression:
		if t.Operator != "!" {
			return fmt.Errorf("expected variable or function")
		}
		return isValidReturnExpression(t.Right)
	case *ast.InfixExpression:
		// Only comparison and boolean operators are allowed
		if !isBooleanOperator(t.Operator) && !isComparisonOperator(t.Operator) {
			return fmt.Errorf("expected ;, got %s", t.Operator)
		}
		return isValidReturnExpression(t.Left)
	}
	return nil
}

// Push regex captured variable to the context if needed
func pushRegexGroupVars(exp ast.Expression, ctx *context.Context) {
	switch t := exp.(type) {
	case *ast.PrefixExpression:
		pushRegexGroupVars(t.Right, ctx)
	case *ast.GroupedExpression:
		pushRegexGroupVars(t.Right, ctx)
	case *ast.InfixExpression:
		if t.Operator == "~" || t.Operator == "!~" {
			// Extract the pattern string from the regex expression
			if str, ok := t.Right.(*ast.String); ok {
				// Count capture groups using PCRE-aware parser
				captureCount := countPCRECaptureGroups(str.Value)
				if captureCount > 0 {
					// +1 because re.group.0 contains the full match
					ctx.PushRegexVariables(captureCount + 1)
				} else {
					ctx.ResetRegexVariables()
				}
			} else {
				// If it's not a string literal, we can't analyze it at compile time
				ctx.ResetRegexVariables()
			}
		} else {
			pushRegexGroupVars(t.Right, ctx)
		}
	}
}

func isBooleanOperator(operator string) bool {
	switch operator {
	case "(":
		return true
	case ")":
		return true
	case "!":
		return true
	case "&&":
		return true
	case "||":
		return true
	}
	return false
}

func isComparisonOperator(operator string) bool {
	switch operator {
	case "==":
		return true
	case "!=":
		return true
	case "~":
		return true
	case "!~":
		return true
	case ">":
		return true
	case "<":
		return true
	case ">=":
		return true
	case "<=":
		return true
	}
	return false
}

func isConstantExpression(exp ast.Expression) bool {
	switch exp.(type) {
	case *ast.Float:
		return true
	case *ast.Integer:
		return true
	case *ast.RTime:
		return true
	}
	return false
}

func isLiteralExpression(exp ast.Expression) bool {
	switch exp.(type) {
	case *ast.Float:
		return true
	case *ast.Integer:
		return true
	case *ast.String:
		return true
	case *ast.RTime:
		return true
	}
	return false
}

func expectType(cur types.Type, expects ...types.Type) bool {
	return slices.Contains(expects, cur)
}

func expectState(cur string, expects ...string) bool {
	return slices.Contains(expects, cur)
}

func annotations(comments ast.Comments) []string {
	var rv []string
	for i := range comments {
		l := strings.TrimLeft(comments[i].Value, " */#")
		if strings.HasPrefix(l, "@") {
			var an []string
			if trimmed, found := strings.CutPrefix(l, "@scope:"); found {
				an = strings.Split(trimmed, ",")
			} else {
				an = strings.Split(strings.TrimPrefix(l, "@"), ",")
			}
			for _, s := range an {
				rv = append(rv, strings.TrimSpace(s))
			}
		}
	}

	return rv
}

func getSubroutineCallScope(s *ast.SubroutineDeclaration) int {
	// Detect phase from subroutine name
	switch {
	case strings.HasSuffix(s.Name.Value, "_recv"):
		return context.RECV
	case strings.HasSuffix(s.Name.Value, "_hash"):
		return context.HASH
	case strings.HasSuffix(s.Name.Value, "_hit"):
		return context.HIT
	case strings.HasSuffix(s.Name.Value, "_miss"):
		return context.MISS
	case strings.HasSuffix(s.Name.Value, "_pass"):
		return context.PASS
	case strings.HasSuffix(s.Name.Value, "_fetch"):
		return context.FETCH
	case strings.HasSuffix(s.Name.Value, "_error"):
		return context.ERROR
	case strings.HasSuffix(s.Name.Value, "_deliver"):
		return context.DELIVER
	case strings.HasSuffix(s.Name.Value, "_log"):
		return context.LOG
	}

	// If could not via subroutine name, find by annotations
	// typically defined in module file
	scopes := 0
	for _, a := range annotations(s.Leading) {
		switch strings.ToUpper(a) {
		case "RECV":
			scopes |= context.RECV
		case "HASH":
			scopes |= context.HASH
		case "HIT":
			scopes |= context.HIT
		case "MISS":
			scopes |= context.MISS
		case "PASS":
			scopes |= context.PASS
		case "FETCH":
			scopes |= context.FETCH
		case "ERROR":
			scopes |= context.ERROR
		case "DELIVER":
			scopes |= context.DELIVER
		case "LOG":
			scopes |= context.LOG
		}
	}
	if scopes == 0 {
		// Unknown scope
		return -1
	}
	return scopes
}

// getFileLevelScope extracts @scope annotation from file-level leading comments.
// This is used for snippet files that have @scope at the beginning of the file.
func getFileLevelScope(vcl *ast.VCL) int {
	if len(vcl.Statements) == 0 {
		return -1
	}

	// Get leading comments from first statement
	meta := vcl.Statements[0].GetMeta()
	if meta == nil {
		return -1
	}

	scopes := 0
	for _, a := range annotations(meta.Leading) {
		switch strings.ToUpper(a) {
		case "RECV":
			scopes |= context.RECV
		case "HASH":
			scopes |= context.HASH
		case "HIT":
			scopes |= context.HIT
		case "MISS":
			scopes |= context.MISS
		case "PASS":
			scopes |= context.PASS
		case "FETCH":
			scopes |= context.FETCH
		case "ERROR":
			scopes |= context.ERROR
		case "DELIVER":
			scopes |= context.DELIVER
		case "LOG":
			scopes |= context.LOG
		}
	}
	if scopes == 0 {
		return -1
	}
	return scopes
}

func enforceSubroutineCallScopeFromConfig(scopeNames []string) int {
	var scopes int
	for i := range scopeNames {
		switch strings.ToUpper(scopeNames[i]) {
		case "RECV":
			scopes |= context.RECV
		case "HASH":
			scopes |= context.HASH
		case "HIT":
			scopes |= context.HIT
		case "MISS":
			scopes |= context.MISS
		case "PASS":
			scopes |= context.PASS
		case "FETCH":
			scopes |= context.FETCH
		case "ERROR":
			scopes |= context.ERROR
		case "DELIVER":
			scopes |= context.DELIVER
		case "LOG":
			scopes |= context.LOG
		}
	}
	if scopes == 0 {
		// Unknown scope
		return -1
	}
	return scopes
}

func isIgnoredSubroutineInConfig(ignores []string, subroutineName string) bool {
	return slices.Contains(ignores, subroutineName)
}

func getFastlySubroutineScope(name string) string {
	switch name {
	case "vcl_recv":
		return "recv"
	case "vcl_hash":
		return "hash"
	case "vcl_hit":
		return "hit"
	case "vcl_miss":
		return "miss"
	case "vcl_pass":
		return "pass"
	case "vcl_fetch":
		return "fetch"
	case "vcl_error":
		return "error"
	case "vcl_deliver":
		return "deliver"
	case "vcl_log":
		return "log"
	}
	return ""
}

// Fastly macro format Must be "#FASTLY [scope]"
// - Comment sign must starts with single "#". "/" sign is not accepted
// - Fixed "FASTLY" string must exactly present without whitespace after comment sign
// - [scope] string is case-insensitive (recv/RECV can be accepcted, typically uppercase)
// - Additional comment is also accepted like "#FASTLY RECV some extra comment"
func hasFastlyBoilerPlateMacro(cs ast.Comments, scope string) bool {
	for _, c := range cs {
		// Uppercase scope
		if strings.HasPrefix(c.String(), "#FASTLY "+strings.ToUpper(scope)) {
			return true
		}
		// lowercase scope
		if strings.HasPrefix(c.String(), "#FASTLY "+strings.ToLower(scope)) {
			return true
		}
	}
	return false
}

// According to fastly share_key must be alphanumeric and ASCII only
func isValidBackendShareKey(shareKey string) bool {
	for _, c := range shareKey {
		if isAlphaNumeric(c) {
			continue
		}
		return false
	}
	return true
}

// According to fastly if a prober is configured with initial < threshold
// then the prober will be marked as unhealthy at the beginning which is can
// cause issues at startup.
func isProbeMakingTheBackendStartAsUnhealthy(prober ast.BackendProbeObject) error {
	var threshold int
	var initial int
	var err error

	// The code below works also if either/both initial and threshold are not present:
	// * if both dont appear then both have values 0 and 0 in which case you get no warning
	// * if initial exists but no threshold then it is also correct because initial > 0 (threshold)
	// * if threshold exists but no initial then we generate an error correctly because threshold > 0 (initial)
	for _, v := range prober.Values {
		if strings.EqualFold(v.Key.Value, "initial") {
			// Optimistically cast this to int, if we can do it because the value is a literal
			// we can apply the check
			initial, err = strconv.Atoi(v.Value.String())
			if err != nil {
				return nil
			}
		}

		if strings.EqualFold(v.Key.Value, "threshold") {
			// Optimistically cast this to int, if we can do it because the value is a literal
			// we can apply the check
			threshold, err = strconv.Atoi(v.Value.String())
			if err != nil {
				return nil
			}
		}
	}

	if threshold > initial {
		return fmt.Errorf("healthcheck initial value is lower than the threshold. Backend will start as unhealthy")
	}

	return nil
}

func isTypeLiteral(node ast.Node) bool {
	switch node.(type) {
	case *ast.IP:
		return true
	case *ast.Boolean:
		return true
	case *ast.Integer:
		return true
	case *ast.String:
		return true
	case *ast.Float:
		return true
	default:
		return false
	}
}

// Some HTTP Headers is protected in Fastly.
// @see https://developer.fastly.com/reference/http/http-headers/
// Consider the character case, we always treat header names as lower-case.
var protectedHeaderNames = map[string]struct{}{
	"req.http.proxy-authenticate":  {},
	"req.http.proxy-authorization": {},
	"req.http.content-length":      {},
	"req.http.content-range":       {},
	"req.http.te":                  {},
	"req.http.trailer":             {},
	"req.http.expect":              {},
	"req.http.transfer-encoding":   {},
	"req.http.upgrade":             {},
	"req.http.fastly-ff":           {},
}

// Check header name exists in protected header names
func isProtectedHTTPHeaderName(name string) bool {
	lower := strings.ToLower(name)
	if _, ok := protectedHeaderNames[lower]; ok {
		return true
	}
	return false
}

// Series expresses the series of string concatenation.
type Series struct {
	Operator   string // Operator will accept either of "+" or "-" or empty string.
	Expression ast.Expression
}

func toSeriesExpressions(expr ast.Expression, ctx *context.Context) ([]*Series, *LintError) {
	switch t := expr.(type) {
	case *ast.Ident:
		// If expression is ident, must be a variable
		// e.g req.http.Header, var.declaredVariable
		if _, err := ctx.Get(t.Value); err != nil {
			switch err {
			case context.ErrDeprecated, context.ErrUncapturedRegexVariable, context.ErrRegexVariableOverridden:
				break
			default:
				return nil, InvalidStringConcatenation(expr.GetMeta(), t.Value)
			}
		}
	case *ast.PrefixExpression:
		if t.Operator != "+" && t.Operator != "-" {
			return nil, InvalidStringConcatenation(expr.GetMeta(), "PrefixExpression")
		}
		s, err := toSeriesExpressions(t.Right, ctx)
		if err != nil {
			return nil, err
		}
		s[0].Operator = t.Operator
		return s, nil
	case *ast.GroupedExpression:
		return nil, InvalidStringConcatenation(expr.GetMeta(), "GroupedExpression")
	case *ast.InfixExpression:
		if t.Operator != "+" {
			return nil, InvalidStringConcatenation(expr.GetMeta(), "InfixExpression")
		}
		var series []*Series
		left, err := toSeriesExpressions(t.Left, ctx)
		if err != nil {
			return nil, err
		}
		series = append(series, left...)

		right, err := toSeriesExpressions(t.Right, ctx)
		if err != nil {
			return nil, err
		}
		if t.Explicit {
			right[0].Operator = t.Operator
		}
		series = append(series, right...)
		return series, nil
	}

	// Concatenatable expression
	return []*Series{
		{Expression: expr},
	}, nil
}
