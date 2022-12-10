package context

type contextKey struct {
	name string
}

var (
	ClientAddrKey   = &contextKey{"tcp-connection"}
	ServerAddrKey   = &contextKey{"server-port"}
	RequestStartKey = &contextKey{"request-started"}
)
