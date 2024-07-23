package token

import (
	"fmt"
)

type TokenType string

type Token struct {
	Type     TokenType
	Literal  string
	Line     int
	Position int
	Offset   int    // for print problem
	File     string // for print problem
	Snippet  bool
}

func (t Token) String() string {
	return fmt.Sprintf(
		"type=%s, literal=`%s`, line=%d, position=%d",
		string(t.Type), t.Literal, t.Line, t.Position,
	)
}

var Null = Token{
	Type:    ILLEGAL,
	Literal: "NULL",
}

const (
	ILLEGAL = "ILLEGAL"
	EOF     = "EOF"

	// Language idents
	IDENT   = "IDENT"
	INT     = "INT"
	STRING  = "STRING"
	FLOAT   = "FLOAT"
	RTIME   = "RTIME"
	COMMENT = "COMMENT"
	TRUE    = "TRUE"
	FALSE   = "FALSE"
	PERCENT = "PERCENT"
	LF      = "LF" // "\n"

	// Operators
	// https://developer.fastly.com/reference/vcl/operators/
	EQUAL              = "EQUAL"              // "=="
	NOT_EQUAL          = "NOTEQUAL"           // "!="
	REGEX_MATCH        = "REGEX"              // "~"
	NOT_REGEX_MATCH    = "NOT_REGEX_MATCH"    // "!~"
	GREATER_THAN       = "GREATER_THAN"       // ">"
	LESS_THAN          = "LESS_THAN"          // "<"
	GREATER_THAN_EQUAL = "GREATER_THAN_EQUAL" // >="
	LESS_THAN_EQUAL    = "LESS_THAN_EQUAL"    // <="
	AND                = "AND"                // "&&"
	OR                 = "OR"                 // "||"

	// Assignment Operators
	// https://developer.fastly.com/reference/vcl/operators/#assignment-operators
	ASSIGN         = "ASSIGN"         // "="
	ADDITION       = "ADDITION"       // "+="
	SUBTRACTION    = "SUBTRACTION"    // "-="
	MULTIPLICATION = "MULTIPLICATION" // "*="
	DIVISION       = "DIVISION"       // "/="
	REMAINDER      = "REMAINDER"      // "%="
	BITWISE_OR     = "BITWISE_OR"     // "|="
	BITWISE_AND    = "BITWISE_AND"    // "&="
	BITWISE_XOR    = "BITWISE_XOR"    // "^="
	LEFT_SHIFT     = "LEFT_SHIFT"     // "<<="
	RIGHT_SHIFT    = "RIGHT_SHIFT"    // ">>="
	LEFT_ROTATE    = "LEFT_ROTATE"    // "rol="
	RIGHT_ROTATE   = "RIGHT_ROTATE"   // "ror="
	LOGICAL_AND    = "LOGICAL_AND"    // "&&="
	LOGICAL_OR     = "LOGICAL_OR"     // "||="

	// Punctuation
	// https://developer.fastly.com/reference/vcl/operators/#reserved-punctuation
	LEFT_BRACE    = "LEFT_BRACE"    // "{"
	RIGHT_BRACE   = "RIGHT_BRACE"   // "}"
	LEFT_PAREN    = "LEFT_PAREN"    // "("
	RIGHT_PAREN   = "RIGHT_PAREN"   // ")"
	LEFT_BRACKET  = "LEFT_BRACKET"  // "["
	RIGHT_BRACKET = "RIGHT_BRACKET" // "]"
	COMMA         = "COMMA"         // ","
	SLASH         = "SLASH"         // "/"
	SEMICOLON     = "SEMICOLON"     // ";"
	DOT           = "DOT"           // "."
	NOT           = "NOT"           // "!"
	COLON         = "COLON"         // ":"
	PLUS          = "PLUS"          // "+"
	MINUS         = "MINUS"         // "-"

	// Keywords
	ACL              = "ACL"              // acl
	DIRECTOR         = "DIRECTOR"         // director
	BACKEND          = "BACKEND"          // backend
	TABLE            = "TABLE"            // table
	SUBROUTINE       = "SUBROUTINE"       // sub
	ADD              = "ADD"              // add
	CALL             = "CALL"             // call
	DECLARE          = "DECLARE"          // declare
	ERROR            = "ERROR"            // error
	ESI              = "ESI"              // esi
	INCLUDE          = "INCLUDE"          // include
	IMPORT           = "IMPORT"           // import
	LOG              = "LOG"              // log"
	REMOVE           = "REMOVE"           // remove
	RESTART          = "RESTART"          // restart
	RETURN           = "RETURN"           // return
	SET              = "SET"              // set
	SYNTHETIC        = "SYNTHETIC"        // synthetic
	SYNTHETIC_BASE64 = "SYNTHETIC_BASE64" // synthetic.base64
	UNSET            = "UNSET"            // unset
	IF               = "IF"               // if
	ELSE             = "ELSE"             // else
	ELSEIF           = "ELSEIF"           // elseif
	ELSIF            = "ELSIF"            // elsif
	PENALTYBOX       = "PENALTYBOX"       // penaltybox
	RATECOUNTER      = "RATECOUNTER"      // ratecounter
	GOTO             = "GOTO"             // goto
	SWITCH           = "SWITCH"           // switch
	CASE             = "CASE"             // case
	DEFAULT          = "DEFAULT"          // default
	BREAK            = "BREAK"            // break
	FALLTHROUGH      = "FALLTHROUGH"      // fallthrough

	// Custom Keywords
	// This keyword is special usecase for extensible language definition.
	// Token is processed via custom lexer/parser definition by literal
	CUSTOM = "CUSTOM"

	// Fastly Generated control syntaxes
	// Fastly automatically generates some control syntaxes like "pragma".
	// falco should lex them
	PRAGMA         = "PRAGMA"
	FASTLY_CONTROL = "CONTROL" // Presents as "C!" or "W!" character
)

var keywords = map[string]TokenType{
	"acl":              ACL,
	"backend":          BACKEND,
	"director":         DIRECTOR,
	"table":            TABLE,
	"sub":              SUBROUTINE,
	"add":              ADD,
	"call":             CALL,
	"declare":          DECLARE,
	"error":            ERROR,
	"esi":              ESI,
	"include":          INCLUDE,
	"import":           IMPORT,
	"log":              LOG,
	"restart":          RESTART,
	"return":           RETURN,
	"set":              SET,
	"synthetic":        SYNTHETIC,
	"unset":            UNSET,
	"if":               IF,
	"else":             ELSE,
	"elseif":           ELSEIF,
	"elsif":            ELSIF,
	"true":             TRUE,
	"false":            FALSE,
	"remove":           REMOVE,
	"synthetic.base64": SYNTHETIC_BASE64,
	"penaltybox":       PENALTYBOX,
	"ratecounter":      RATECOUNTER,
	"goto":             GOTO,
	"switch":           SWITCH,
	"case":             CASE,
	"default":          DEFAULT,
	"break":            BREAK,
	"fallthrough":      FALLTHROUGH,
	"pragma":           PRAGMA,
}

func LookupIdent(ident string) TokenType {
	if v, ok := keywords[ident]; ok {
		return v
	}

	return IDENT
}
