package types

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

type Permission int

const (
	PermissionDeny   Permission = 0x0000
	PermissionGet   Permission = 0x0001
	PermissionSet   Permission = 0x0010
	PermissionUnset Permission = 0x0100
	PermissionAny   Permission = 0x1111
)

func (p Permission) String() string {
	switch p {
	case PermissionGet:
		return "get"
	case PermissionSet:
		return "set"
	case PermissionUnset:
		return "unset"
	default:
		return "ANY"
	}
}

