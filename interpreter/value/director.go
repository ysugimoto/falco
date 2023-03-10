package value

type DirectorConfig struct {
	Type     string
	Name     string
	Quorum   int
	Retries  int
	Backends []*DirectorConfigBackend
}

type DirectorConfigBackend struct {
	Backend *Backend
	Id      string
	Weight  int
}
