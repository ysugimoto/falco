package context

type Scope int

const (
	InitScope    Scope = 0x000000000
	RecvScope    Scope = 0x000000001
	HashScope    Scope = 0x000000010
	HitScope     Scope = 0x000000100
	MissScope    Scope = 0x000001000
	PassScope    Scope = 0x000010000
	FetchScope   Scope = 0x000100000
	ErrorScope   Scope = 0x001000000
	DeliverScope Scope = 0x010000000
	LogScope     Scope = 0x100000000
	AnyScope     Scope = 0x111111111
)

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
