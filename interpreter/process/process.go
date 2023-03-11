package process

import (
	"encoding/json"
	"time"

	"github.com/ysugimoto/falco/interpreter/value"
)

type Process struct {
	Flows     []*Flow
	Logs      []*Log
	Restarts  int
	Backend   *value.Backend
	Cached    bool
	Error     error
	StartTime int64
}

func New() *Process {
	return &Process{
		Flows:     []*Flow{},
		Logs:      []*Log{},
		StartTime: time.Now().UnixMicro(),
	}
}

func (p *Process) MarshalJSON() ([]byte, error) {
	var backend string
	if p.Backend != nil {
		backend = p.Backend.Value.Name.Value
	}

	return json.Marshal(struct {
		Flows         []*Flow `json:"flows"`
		Logs          []*Log  `json:"logs"`
		Restarts      int     `json:"restarts"`
		Backend       string  `json:"backend"`
		Cached        bool    `json:"cached"`
		ElapsedTimeUs int64   `json:"elapsed_time_us"`
		ElapsedTimeMs int64   `json:"elapsed_time_ms"`
		Error         error   `json:"error,omitempty"`
	}{
		Flows:         p.Flows,
		Logs:          p.Logs,
		Restarts:      p.Restarts,
		Backend:       backend,
		Cached:        false,
		ElapsedTimeUs: time.Now().UnixMicro() - p.StartTime,
		ElapsedTimeMs: time.Now().UnixMilli() - (p.StartTime / 1000),
		Error:         p.Error,
	})
}
