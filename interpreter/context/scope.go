package context

import "strings"

type Scope int

const (
	UnknownScope Scope = 0x0000000000
	InitScope    Scope = 0x0000000001
	RecvScope    Scope = 0x0000000010
	HashScope    Scope = 0x0000000100
	HitScope     Scope = 0x0000001000
	MissScope    Scope = 0x0000010000
	PassScope    Scope = 0x0000100000
	FetchScope   Scope = 0x0001000000
	ErrorScope   Scope = 0x0010000000
	DeliverScope Scope = 0x0100000000
	LogScope     Scope = 0x1000000000
	AnyScope     Scope = 0x1111111111
)

func ScopeByString(s string) Scope {
	switch strings.ToUpper(s) {
	case "INIT":
		return InitScope
	case "RECV":
		return RecvScope
	case "HASH":
		return HashScope
	case "HIT":
		return HitScope
	case "MISS":
		return MissScope
	case "PASS":
		return PassScope
	case "FETCH":
		return FetchScope
	case "ERROR":
		return ErrorScope
	case "DELIVER":
		return DeliverScope
	case "LOG":
		return LogScope
	default:
		return UnknownScope
	}
}

func (s Scope) String() string {
	switch s {
	case InitScope:
		return "INIT"
	case RecvScope:
		return "RECV"
	case HashScope:
		return "HASH"
	case HitScope:
		return "HIT"
	case MissScope:
		return "MISS"
	case PassScope:
		return "PASS"
	case FetchScope:
		return "FETCH"
	case ErrorScope:
		return "ERROR"
	case DeliverScope:
		return "DELIVER"
	case LogScope:
		return "LOG"
	case AnyScope:
		return "ANY"
	default:
		return "UNKNOWN"
	}
}

func (s Scope) Is(scopes ...Scope) bool {
	var scope int
	for _, v := range scopes {
		scope |= int(v)
	}
	return (int(s) & scope) > 0
}
