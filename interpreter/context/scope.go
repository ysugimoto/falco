package context

import "strings"

type Scope int

const (
	UnknownScope Scope = 0x00000000000
	InitScope    Scope = 0x00000000001
	RecvScope    Scope = 0x00000000010
	HashScope    Scope = 0x00000000100
	HitScope     Scope = 0x00000001000
	MissScope    Scope = 0x00000010000
	PassScope    Scope = 0x00000100000
	FetchScope   Scope = 0x00001000000
	ErrorScope   Scope = 0x00010000000
	DeliverScope Scope = 0x00100000000
	LogScope     Scope = 0x01000000000
	PipeScope    Scope = 0x10000000000
	AnyScope     Scope = 0x11111111111
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
	case "PIPE":
		return PipeScope
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
	case PipeScope:
		return "PIPE"
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
