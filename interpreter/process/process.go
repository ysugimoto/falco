package process

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	flchttp "github.com/ysugimoto/falco/interpreter/http"
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
	Response  *http.Response
}

func New() *Process {
	return &Process{
		Flows:     []*Flow{},
		Logs:      []*Log{},
		StartTime: time.Now().UnixMicro(),
	}
}

func (p *Process) Finalize(resp *flchttp.Response) ([]byte, error) {
	var backend string
	if p.Backend != nil {
		backend = p.Backend.Value.Name.Value
	}

	var statusCode int
	var buf bytes.Buffer
	headers := make(map[string]string)

	if resp != nil {
		statusCode = resp.StatusCode
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return nil, err
		}
		// rewind response body - may not need but guard from another body retrieving
		resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))

		for key, val := range resp.Header {
			if len(val) == 0 {
				continue
			}
			for _, vs := range val {
				var vss []string
				for _, v := range vs {
					line := v.Key.String()
					if v.Value != nil {
						line += "=" + v.Value.String()
					}
					vss = append(vss, key+": "+line)
				}
				headers[strings.ToLower(key)] = strings.Join(vss, "; ")
			}
		}
	}

	return json.MarshalIndent(struct {
		Flows          []*Flow `json:"flows"`
		Logs           []*Log  `json:"logs"`
		Restarts       int     `json:"restarts"`
		Backend        string  `json:"backend"`
		Cached         bool    `json:"cached"`
		ElapsedTimeUs  int64   `json:"elapsed_time_us"`
		ElapsedTimeMs  int64   `json:"elapsed_time_ms"`
		Error          error   `json:"error,omitempty"`
		ClientResponse struct {
			StatusCode    int               `json:"status_code"`
			ResponseBytes int               `json:"body_bytes"`
			Headers       map[string]string `json:"headers"`
		} `json:"client_response"`
	}{
		Flows:         p.Flows,
		Logs:          p.Logs,
		Restarts:      p.Restarts,
		Backend:       backend,
		Cached:        false,
		ElapsedTimeUs: time.Now().UnixMicro() - p.StartTime,
		ElapsedTimeMs: time.Now().UnixMilli() - (p.StartTime / 1000),
		Error:         p.Error,
		ClientResponse: struct {
			StatusCode    int               `json:"status_code"`
			ResponseBytes int               `json:"body_bytes"`
			Headers       map[string]string `json:"headers"`
		}{
			StatusCode:    statusCode,
			ResponseBytes: len(buf.Bytes()),
			Headers:       headers,
		},
	}, "", "  ")
}
