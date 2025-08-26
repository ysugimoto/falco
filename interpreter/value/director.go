package value

type DirectorConfig struct {
	Type          string // director type
	Name          string // director name
	Quorum        int    // only exists on random, hash, client and chash
	Retries       int    // only exists on random
	Key           string // only exists on chash
	Seed          uint32 // only exists on chash
	VNodesPerNode int    // only exists on chash
	Backends      []*DirectorConfigBackend
}

type DirectorConfigBackend struct {
	Backend *Backend
	Id      string
	Weight  int
}

const (
	DIRECTORTYPE_RANDOM   = "random"
	DIRECTORTYPE_FALLBACK = "fallback"
	DIRECTORTYPE_HASH     = "hash"
	DIRECTORTYPE_CLIENT   = "client"
	DIRECTORTYPE_CHASH    = "chash"
	DIRECTORTYPE_SHIELD   = "shield"
)
