package linter

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/types"
)

var captureRegex = regexp.MustCompile(`\([^\)]+\)`)

var BackendPropertyTypes = map[string]types.Type{
	"dynamic":                types.BoolType,
	"share_key":              types.StringType,
	"host":                   types.StringType,
	"port":                   types.StringType,
	"ssl":                    types.BoolType,
	"ssl_cert_hostname":      types.StringType,
	"ssl_check_cert":         types.IDType,
	"ssl_sni_hostname":       types.StringType,
	"between_bytes_timeout":  types.RTimeType,
	"connect_timeout":        types.RTimeType,
	"first_byte_timeout":     types.RTimeType,
	"max_connections":        types.IntegerType,
	"host_header":            types.StringType,
	"always_use_host_header": types.BoolType,
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
			"quorum":  types.StringType,
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
			"quorum":  types.StringType,
			"backend": types.BackendType,
			"weight":  types.IntegerType,
		},
		Requires: []string{"weight"},
	},
	"client": {
		Rule: DIRECTOR_PROPS_CLIENT,
		Props: map[string]types.Type{
			"quorum":  types.StringType,
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
			"quorum":          types.StringType,
			"weight":          types.IntegerType,
			"id":              types.StringType,
		},
		Requires: []string{"id"},
	},
}

var ValueTypeMap = map[string]types.Type{
	"INTEGER": types.IntegerType,
	"FLOAT":   types.FloatType,
	"BOOL":    types.BoolType,
	"ACL":     types.AclType,
	"BACKEND": types.BackendType,
	"IP":      types.IPType,
	"STRING":  types.StringType,
	"ID":      types.IDType,
	"RTIME":   types.RTimeType,
	"TIME":    types.TimeType,
}

func isAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_'
}

// isValidName validates ident name has only [0-9a-zA-Z_]+
func isValidName(name string) bool {
	for _, r := range name {
		if isAlphaNumeric(r) {
			continue
		}
		return false
	}
	return true
}

// isValidVariableName validates ident name has only [0-9a-zA-Z_\.-:]+
func isValidVariableName(name string) bool {
	for _, r := range name {
		if isAlphaNumeric(r) || r == '.' || r == '-' || r == ':' {
			continue
		}
		return false
	}
	return true
}

// In VCL, could not specify literal in if condition expression.
//
// if (!req.http.Cookie) { ... } // -> valid, inverse actual dentity variable (implicit type conversion will occur)
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
			return fmt.Errorf("Could not specify literal in first expression")
		}
	}
	return nil
}

// In VCL, bang operator could not use in set/add statement expression,
// and only string concatenation expression could use.
//
// declare local var.Foo BOOL;
// declare local var.Bar STRING;
// set var.Bar = "foo" "bar";                      // -> valid, string concatenation operator can use
// set var.Foo = (req.http.Host == "example.com"); // -> valid, equal operator cau use inside grouped expression set statement
// set var.Foo = !false;                           // -> invalid, could not use in set statement
// set var.Foo = req.http.Host == "example.com";   // -> invalid, equal operator could not use in set statement
//
// So we'd check validity following function.
func isValidStatmentExpression(exp ast.Expression) error {
	switch t := exp.(type) {
	case *ast.PrefixExpression:
		if t.Operator == "!" {
			return fmt.Errorf("Could not specify bang operator in first expression")
		}
	case *ast.InfixExpression:
		if t.Operator != "+" {
			return fmt.Errorf("Could not specify %s operator in statement", t.Operator)
		}
	}
	return nil
}

func pushRegexGroupVars(exp ast.Expression, ctx *context.Context) error {
	switch t := exp.(type) {
	case *ast.PrefixExpression:
		return pushRegexGroupVars(t.Right, ctx)
	case *ast.InfixExpression:
		if t.Operator == "~" || t.Operator == "!~" {
			m := captureRegex.FindAllStringSubmatch(t.Right.String(), -1)
			if m != nil {
				return ctx.PushRegexVariables(len(m) + 1)
			}
		} else {
			return pushRegexGroupVars(t.Right, ctx)
		}
	}
	return nil
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
	for i := range expects {
		if expects[i] == cur {
			return true
		}
	}
	return false
}

func expectState(cur string, expects ...string) bool {
	for i := range expects {
		if expects[i] == cur {
			return true
		}
	}
	return false
}

func annotations(comments ast.Comments) []string {
	var a []string

	for i := range comments {
		l := strings.TrimLeft(comments[i].Value, " */#")
		if strings.HasPrefix(l, "@") {
			a = append(a, strings.TrimPrefix(l, "@"))
		}
	}

	return a
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
	// typically defined is module file
	for _, a := range annotations(s.Leading) {
		switch strings.ToUpper(a) {
		case "RECV":
			return context.RECV
		case "HASH":
			return context.HASH
		case "HIT":
			return context.HIT
		case "MISS":
			return context.MISS
		case "PASS":
			return context.PASS
		case "FETCH":
			return context.FETCH
		case "ERROR":
			return context.ERROR
		case "DELIVER":
			return context.DELIVER
		case "LOG":
			return context.LOG
		}
	}
	return context.RECV
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
