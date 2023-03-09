package process

import (
	"encoding/json"

	"github.com/ysugimoto/falco/interpreter/value"
)

type Process struct {
	Flows    []*Flow
	Logs     []*Log
	Restarts int
	Backend  *value.Backend
	Cached   bool
}

func New() *Process {
	return &Process{
		Flows: []*Flow{},
		Logs:  []*Log{},
	}
}

func (p *Process) MarshalJSON() ([]byte, error) {
	var backend string
	if p.Backend != nil {
		backend = p.Backend.Value.Name.Value
	}

	return json.Marshal(struct {
		Flows    []*Flow `json:"flows"`
		Logs     []*Log  `json:"logs"`
		Restarts int     `json:"restarts"`
		Backend  string  `json:"backend"`
		Cached   bool    `json:"cached"`
	}{
		Flows:    p.Flows,
		Logs:     p.Logs,
		Restarts: p.Restarts,
		Backend:  backend,
		Cached:   false,
	})
}
