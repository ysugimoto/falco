package interpreter

import (
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/value"
)

var (
	ErrQuorumWeightNotReached = errors.New("Quorum weight not reached")
	ErrAllBackendsFailed      = errors.New("All backend failed")
)

func (i *Interpreter) getDirectorConfig(d *ast.DirectorDeclaration) (*value.DirectorConfig, error) {
	conf := &value.DirectorConfig{
		Name: d.Name.Value,
	}

	// Validate director type
	switch d.DirectorType.Value {
	case "random", "fallback", "hash", "client", "chash":
		conf.Type = d.DirectorType.Value
	default:
		return nil, exception.Runtime(
			&d.DirectorType.GetMeta().Token,
			"Unrecognized director type '%s' provided",
			d.DirectorType.Value,
		)
	}

	// Parse director properties
	for _, prop := range d.Properties {
		switch t := prop.(type) {
		case *ast.DirectorBackendObject:
			backend := &value.DirectorConfigBackend{}
			for _, p := range t.Values {
				switch p.Key.Value {
				case "backend":
					if v, ok := p.Value.(*ast.Ident); !ok {
						return nil, exception.Runtime(
							&p.GetMeta().Token,
							"backend value must be percentage prefixed value",
						)
					} else if b, ok := i.ctx.Backends[v.Value]; !ok {
						return nil, exception.Runtime(&p.GetMeta().Token, "backend '%s' is not found", v.Value)
					} else {
						backend.Backend = b
					}
				case "id":
					if v, ok := p.Value.(*ast.String); !ok {
						return nil, exception.Runtime(&p.GetMeta().Token, "id value must be a string")
					} else {
						backend.Id = v.Value
					}
				case "weight":
					if v, ok := p.Value.(*ast.Integer); !ok {
						return nil, exception.Runtime(&p.GetMeta().Token, "weight value must be an integer")
					} else {
						backend.Weight = int(v.Value)
					}
				default:
					return nil, exception.Runtime(
						&p.GetMeta().Token,
						"Unexpected director backend property '%s' found",
						p.Key.Value,
					)
				}
			}

			// Validate reqired properties
			switch conf.Type {
			case "random", "fallback", "hash", "client":
				if backend.Weight == 0 {
					return nil, exception.Runtime(
						&t.GetMeta().Token,
						".weight property must be set when director type is '%s'",
						conf.Type,
					)
				}
			case "chash":
				if backend.Id == "" {
					return nil, exception.Runtime(
						&t.GetMeta().Token,
						".id property must be set when director type is '%s'",
						conf.Type,
					)
				}
			}
			conf.Backends = append(conf.Backends, backend)
		case *ast.DirectorProperty:
			switch t.Key.Value {
			case "quorum":
				if v, ok := t.Value.(*ast.String); !ok {
					return nil, exception.Runtime(
						&t.GetMeta().Token,
						"quorum value must be percentage prefixed value",
					)
				} else if n, err := strconv.Atoi(strings.TrimSuffix(v.Value, "%")); err != nil {
					return nil, exception.Runtime(
						&t.GetMeta().Token,
						"Invalid quorum value '%s' found. Value must be percentage string like '50%'",
						v.Value,
					)
				} else {
					conf.Quorum = n
				}
			case "retries":
				if v, ok := t.Value.(*ast.Integer); !ok {
					return nil, exception.Runtime(
						&t.GetMeta().Token,
						"retries value must be integer",
					)
				} else {
					conf.Retries = int(v.Value)
				}
			default:
				return nil, exception.Runtime(
					&t.GetMeta().Token,
					"Unexpected director property '%s' found",
					t.Key.Value,
				)
			}
		default:
			return nil, exception.Runtime(
				&t.GetMeta().Token,
				"Unexpected field expression '%s' found",
				t.String(),
			)
		}
	}

	if len(conf.Backends) == 0 {
		return nil, exception.Runtime(
			&d.GetMeta().Token,
			"At least one backend must be specified in director '%s'",
			conf.Name,
		)
	}

	return conf, nil
}

func (i *Interpreter) createDirectorRequest(dc *value.DirectorConfig) (*http.Request, error) {
	var backend *value.Backend
	var err error

	switch dc.Type {
	case "random":
		backend, err = i.directorBackendRandom(dc)
	case "fallback":
		backend, err = i.directorBackendFallback(dc)
	case "hash":
		backend, err = i.directorBackendHash(dc)
	case "client":
		backend, err = i.directorBackendClient(dc)
	case "chash":
		backend, err = i.directorBackendConsistentHash(dc)
	default:
		return nil, exception.System("Unexpected director type '%s' provided", dc.Type)
	}

	if err != nil {
		return nil, errors.WithStack(err)
	}
	return i.createBackendRequest(backend)
}

// Random director
// https://developer.fastly.com/reference/vcl/declarations/director/#random
func (i *Interpreter) directorBackendRandom(dc *value.DirectorConfig) (*value.Backend, error) {
	// For random director, .retries value should use backend count as default.
	maxRetry := dc.Retries
	if maxRetry == 0 {
		maxRetry = len(dc.Backends)
	}

	for retry := 0; retry < maxRetry; retry++ {
		lottery := make([]int, 1000)
		var current, healthyBackends int
		for index, v := range dc.Backends {
			// Skip if backend is unhealthy
			if !v.Backend.Healthy.Load() {
				continue
			}
			healthyBackends++
			for i := 0; i < v.Weight; i++ {
				lottery[current] = index
				current++
			}
		}

		// Check quorum percentage
		if healthyBackends/len(dc.Backends) < dc.Quorum {
			// @SPEC: random director waits 10ms until retry backend detection
			time.Sleep(10 * time.Millisecond)
			continue
		}

		rand.Seed(time.Now().Unix())
		lottery = lottery[0:current]
		item := dc.Backends[lottery[rand.Intn(current)]]

		return item.Backend, nil
	}

	return nil, ErrQuorumWeightNotReached
}

// Fallback director
// https://developer.fastly.com/reference/vcl/declarations/director/#fallback
func (i *Interpreter) directorBackendFallback(dc *value.DirectorConfig) (*value.Backend, error) {
	for _, v := range dc.Backends {
		if v.Backend.Healthy.Load() {
			return v.Backend, nil
		}
	}

	return nil, ErrAllBackendsFailed
}

func (i *Interpreter) directorBackendHash(dc *value.DirectorConfig) (*value.Backend, error) {
	return nil, nil
}

func (i *Interpreter) directorBackendClient(dc *value.DirectorConfig) (*value.Backend, error) {
	return nil, nil
}

func (i *Interpreter) directorBackendConsistentHash(dc *value.DirectorConfig) (*value.Backend, error) {
	return nil, nil
}
