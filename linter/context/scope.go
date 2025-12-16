package context

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
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
		return errors.New(message)
	}
	return nil
}
