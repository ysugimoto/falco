package linter

type Rule string

func (r Rule) Reference() string {
	if v, ok := references[r]; ok {
		return v
	}
	return ""
}

const (
	ACL_SYNTAX                           = "acl/syntax"
	ACL_DUPLICATED                       = "acl/duplicated"
	BACKEND_SYNTAX                       = "backend/syntax"
	BACKEND_DUPLICATED                   = "backend/duplicated"
	BACKEND_NOTFOUND                     = "backend/notfound"
	DIRECTOR_SYNTAX                      = "director/syntax"
	DIRECTOR_DUPLICATED                  = "director/duplicated"
	DIRECTOR_PROPS_RANDOM                = "director/props-random"
	DIRECTOR_PROPS_FALLBACK              = "director/props-fallback"
	DIRECTOR_PROPS_HASH                  = "director/props-hash"
	DIRECTOR_PROPS_CLIENT                = "director/props-client"
	DIRECTOR_PROPS_CHASH                 = "director/props-chash"
	DIRECTOR_BACKEND_REQUIRED            = "director/backend-required"
	TABLE_SYNTAX                         = "table/syntax"
	TABLE_TYPE_VARIATION                 = "table/type-variation"
	TABLE_ITEM_LIMITATION                = "table/item-limitation"
	TABLE_DUPLICATED                     = "table/duplicated"
	SUBROUTINE_SYNTAX                    = "subroutine/syntax"
	SUBROUTINE_BOILERPLATE_MACRO         = "subroutine/boilerplate-macro"
	SUBROUTINE_DUPLICATED                = "subroutine/duplicated"
	SUBROUTINE_INVALID_RETURN_TYPE       = "subroutine/invalid-return-type"
	PENALTYBOX_SYNTAX                    = "penaltybox/syntax"
	PENALTYBOX_DUPLICATED                = "penaltybox/duplicated"
	PENALTYBOX_NONEMPTY_BLOCK            = "penaltybox/nonempty-block"
	RATECOUNTER_SYNTAX                   = "ratecounter/syntax"
	RATECOUNTER_DUPLICATED               = "ratecounter/duplicated"
	RATECOUNTER_NONEMPTY_BLOCK           = "ratecounter/nonempty-block"
	DECLARE_STATEMENT_SYNTAX             = "declare-statement/syntax"
	DECLARE_STATEMENT_INVALID_TYPE       = "declare-statement/invalid-type"
	DECLARE_STATEMENT_DUPLICATED         = "declare-statement/duplicated"
	SET_STATEMENT_SYNTAX                 = "set-statement/syntax"
	OPERATOR_ASSIGNMENT                  = "operator/assignment"
	UNSET_STATEMENT_SYNTAX               = "unset-statement/syntax"
	REMOVE_STATEMENT_SYNTAX              = "remote-statement/syntax"
	OPERATOR_CONDITIONAL                 = "operator/conditional"
	RESTART_STATEMENT_SCOPE              = "restart-statement/scope"
	ADD_STATEMENT_SYNTAX                 = "add-statement/syntax"
	CALL_STATEMENT_SYNTAX                = "call-statement/syntax"
	CALL_STATEMENT_SUBROUTINE_NOTFOUND   = "call-statement/subroutine-notfound"
	ERROR_STATEMENT_SCOPE                = "error-statement/scope"
	ERROR_STATEMENT_CODE                 = "error-statement/code"
	SYNTHETIC_STATEMENT_SCOPE            = "synthetic-statement/scope"
	SYNTHETIC_BASE64_STATEMENT_SCOPE     = "synthetic-base64-statement/scope"
	CONDITION_LITERAL                    = "condition/literal"
	VALID_IP                             = "valid-ip"
	FUNCTION_ARGUMENTS                   = "function/arguments"
	FUNCTION_ARGUMENT_TYPE               = "function/argument-type"
	INCLUDE_STATEMENT_MODULE_NOT_FOUND   = "include/module-not-found"
	INCLUDE_STATEMENT_MODULE_LOAD_FAILED = "include/module-load-failed"
	REGEX_MATCHED_VALUE_MAY_OVERRIDE     = "regex/matched-value-override"
	UNUSED_DECLARATION                   = "unused/declaration"
	UNUSED_VARIABLE                      = "unused/variable"
)

var references = map[Rule]string{
	ACL_SYNTAX:                       "https://developer.fastly.com/reference/vcl/declarations/acl/",
	BACKEND_SYNTAX:                   "https://developer.fastly.com/reference/vcl/declarations/backend/",
	DIRECTOR_SYNTAX:                  "https://developer.fastly.com/reference/vcl/declarations/director/",
	DIRECTOR_PROPS_RANDOM:            "https://developer.fastly.com/reference/vcl/declarations/director/#random",
	DIRECTOR_PROPS_FALLBACK:          "https://developer.fastly.com/reference/vcl/declarations/director/#fallback",
	DIRECTOR_PROPS_HASH:              "https://developer.fastly.com/reference/vcl/declarations/director/#content",
	DIRECTOR_PROPS_CLIENT:            "https://developer.fastly.com/reference/vcl/declarations/director/#client",
	DIRECTOR_PROPS_CHASH:             "https://developer.fastly.com/reference/vcl/declarations/director/#consistent-hashing",
	TABLE_SYNTAX:                     "https://developer.fastly.com/reference/vcl/declarations/table/",
	TABLE_TYPE_VARIATION:             "https://developer.fastly.com/reference/vcl/declarations/table/#type-variations",
	TABLE_ITEM_LIMITATION:            "https://developer.fastly.com/reference/vcl/declarations/table/#limitations",
	SUBROUTINE_SYNTAX:                "https://developer.fastly.com/reference/vcl/subroutines/",
	SUBROUTINE_BOILERPLATE_MACRO:     "https://developer.fastly.com/learning/vcl/using/#adding-vcl-to-your-service-configuration",
	PENALTYBOX_SYNTAX:                "https://developer.fastly.com/reference/vcl/declarations/penaltybox/",
	PENALTYBOX_NONEMPTY_BLOCK:        "https://developer.fastly.com/reference/vcl/declarations/penaltybox/",
	RATECOUNTER_SYNTAX:               "https://developer.fastly.com/reference/vcl/declarations/ratecounter/",
	RATECOUNTER_NONEMPTY_BLOCK:       "https://developer.fastly.com/reference/vcl/declarations/ratecounter/",
	DECLARE_STATEMENT_SYNTAX:         "https://developer.fastly.com/reference/vcl/variables/#user-defined-variables",
	DECLARE_STATEMENT_INVALID_TYPE:   "https://developer.fastly.com/reference/vcl/variables/#user-defined-variables",
	SET_STATEMENT_SYNTAX:             "https://developer.fastly.com/reference/vcl/statements/set/",
	OPERATOR_ASSIGNMENT:              "https://developer.fastly.com/reference/vcl/operators/#assignment-operators",
	UNSET_STATEMENT_SYNTAX:           "https://developer.fastly.com/reference/vcl/statements/unset/",
	REMOVE_STATEMENT_SYNTAX:          "https://developer.fastly.com/reference/vcl/statements/remove/",
	OPERATOR_CONDITIONAL:             "https://developer.fastly.com/reference/vcl/operators/#conditional-operators",
	RESTART_STATEMENT_SCOPE:          "https://developer.fastly.com/reference/vcl/statements/restart/",
	ADD_STATEMENT_SYNTAX:             "https://developer.fastly.com/reference/vcl/statements/add/",
	CALL_STATEMENT_SYNTAX:            "https://developer.fastly.com/reference/vcl/statements/call/",
	ERROR_STATEMENT_SCOPE:            "https://developer.fastly.com/reference/vcl/statements/error/",
	ERROR_STATEMENT_CODE:             "https://developer.fastly.com/reference/vcl/statements/error/#best-practices-for-using-status-codes-for-errors",
	SYNTHETIC_STATEMENT_SCOPE:        "https://developer.fastly.com/reference/vcl/statements/synthetic/",
	SYNTHETIC_BASE64_STATEMENT_SCOPE: "https://developer.fastly.com/reference/vcl/statements/synthetic-base64/",
}
