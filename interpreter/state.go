package interpreter

import "strings"

type State string

const (
	NONE           State = ""
	LOOKUP         State = "lookup"
	PASS           State = "pass"
	HASH           State = "hash"
	ERROR          State = "error"
	RESTART        State = "restart"
	DELIVER        State = "deliver"
	FETCH          State = "fetch"
	DELIVER_STALE  State = "deliver_stale"
	LOG            State = "log"
	END            State = "end"
	INTERNAL_ERROR State = "_internal_error_"
	BARE_RETURN    State = "_bare_return_"
)

func (s State) String() string {
	switch s {
	case LOOKUP:
		return "lookup"
	case PASS:
		return "pass"
	case HASH:
		return "hash"
	case ERROR:
		return "error"
	case RESTART:
		return "restart"
	case DELIVER:
		return "deliver"
	case FETCH:
		return "fetch"
	case DELIVER_STALE:
		return "deliver_stale"
	case LOG:
		return "log"
	case END:
		return "end"
	case INTERNAL_ERROR:
		return "_internal_error_"
	case BARE_RETURN:
		return "_bare_return_"
	default:
		return ""
	}
}

var stateMap = map[string]State{
	"lookup":        LOOKUP,
	"pass":          PASS,
	"hash":          HASH,
	"error":         ERROR,
	"restart":       RESTART,
	"deliver":       DELIVER,
	"fetch":         FETCH,
	"deliver_stale": DELIVER_STALE,
	"log":           LOG,
	"end":           END,
}

func StateFromString(s string) State {
	if v, ok := stateMap[strings.ToLower(s)]; ok {
		return v
	}
	return NONE
}
