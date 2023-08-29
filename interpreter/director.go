package interpreter

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/value"
)

const (
	DIRECTORTYPE_RANDOM   = "random"
	DIRECTORTYPE_FALLBACK = "fallback"
	DIRECTORTYPE_HASH     = "hash"
	DIRECTORTYPE_CLIENT   = "client"
	DIRECTORTYPE_CHASH    = "chash"
)

var (
	ErrQuorumWeightNotReached = errors.New("Quorum weight not reached")
	ErrAllBackendsFailed      = errors.New("All backend failed")
)

func (i *Interpreter) getDirectorConfigBackend(o *ast.DirectorBackendObject) (*value.DirectorConfigBackend, error) {
	backend := &value.DirectorConfigBackend{}
	for _, p := range o.Values {
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
	return backend, nil
}

func (i *Interpreter) setDirectorConfigProperty(conf *value.DirectorConfig, prop *ast.DirectorProperty) error {
	switch prop.Key.Value {
	case "quorum":
		if conf.Type == DIRECTORTYPE_FALLBACK {
			return exception.Runtime(
				&prop.GetMeta().Token,
				".quorum field must not be present in fallback director type",
			)
		}
		if v, ok := prop.Value.(*ast.String); !ok {
			return exception.Runtime(
				&prop.GetMeta().Token,
				"quorum value must be percentage prefixed value",
			)
		} else if n, err := strconv.Atoi(strings.TrimSuffix(v.Value, "%")); err != nil {
			return exception.Runtime(
				&prop.GetMeta().Token,
				"Invalid quorum value '%s' found. Value must be percentage string like '50%%'",
				v.Value,
			)
		} else {
			conf.Quorum = n
		}
		return nil
	case "retries":
		if conf.Type != DIRECTORTYPE_RANDOM {
			return exception.Runtime(
				&prop.GetMeta().Token,
				".retries field must be present only in random director type",
			)
		}
		if v, ok := prop.Value.(*ast.Integer); !ok {
			return exception.Runtime(&prop.GetMeta().Token, "retries value must be integer")
		} else {
			conf.Retries = int(v.Value)
		}
		return nil
	case "key":
		if conf.Type != DIRECTORTYPE_CHASH {
			return exception.Runtime(
				&prop.GetMeta().Token,
				".key field must be present only in chash director type",
			)
		}
		if v, ok := prop.Value.(*ast.Ident); !ok {
			return exception.Runtime(&prop.GetMeta().Token, ".key value must be integer")
		} else if v.Value != "object" && v.Value != "client" {
			return exception.Runtime(&prop.GetMeta().Token, ".key value must be either of object or client")
		} else {
			conf.Key = v.Value
		}
		return nil
	case "seed":
		if conf.Type != DIRECTORTYPE_CHASH {
			return exception.Runtime(
				&prop.GetMeta().Token,
				".seed field must be present only in chash director type",
			)
		}
		if v, ok := prop.Value.(*ast.Integer); !ok {
			return exception.Runtime(&prop.GetMeta().Token, ".seed value must be integer")
		} else {
			conf.Seed = uint32(v.Value)
		}
		return nil
	case "vnodes_per_node":
		if conf.Type != DIRECTORTYPE_CHASH {
			return exception.Runtime(
				&prop.GetMeta().Token,
				".vnodes_per_node field must be present only in chash director type",
			)
		}
		if v, ok := prop.Value.(*ast.Integer); !ok {
			return exception.Runtime(&prop.GetMeta().Token, ".vnodes_per_node value must be integer")
		} else if v.Value > 8_388_608 {
			// vnodes_per_node value is limted under 8,388,608
			// see: https://developer.fastly.com/reference/vcl/declarations/director/#consistent-hashing
			return exception.Runtime(&prop.GetMeta().Token, ".vnodes_per_node value is limited under 8388608")
		} else {
			conf.VNodesPerNode = int(v.Value)
		}
		return nil
	}
	return exception.Runtime(&prop.GetMeta().Token, "Unexpected director property '%s' found", prop.Key.Value)
}

func (i *Interpreter) getDirectorConfig(d *ast.DirectorDeclaration) (*value.DirectorConfig, error) {
	conf := &value.DirectorConfig{
		Name: d.Name.Value,
	}

	// Validate director type
	switch d.DirectorType.Value {
	case DIRECTORTYPE_RANDOM,
		DIRECTORTYPE_FALLBACK,
		DIRECTORTYPE_HASH,
		DIRECTORTYPE_CLIENT,
		DIRECTORTYPE_CHASH:
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
			backend, err := i.getDirectorConfigBackend(t)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			// Validate reqired properties
			switch conf.Type {
			case DIRECTORTYPE_RANDOM, DIRECTORTYPE_HASH, DIRECTORTYPE_CLIENT:
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
			if err := i.setDirectorConfigProperty(conf, t); err != nil {
				return nil, errors.WithStack(err)
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

func (i *Interpreter) createDirectorRequest(ctx *context.Context, dc *value.DirectorConfig) (*http.Request, error) {
	var backend *value.Backend
	var err error

	switch dc.Type {
	case DIRECTORTYPE_RANDOM:
		backend, err = i.directorBackendRandom(dc)
	case DIRECTORTYPE_FALLBACK:
		backend, err = i.directorBackendFallback(dc)
	case DIRECTORTYPE_HASH:
		backend, err = i.directorBackendHash(dc)
	case DIRECTORTYPE_CLIENT:
		backend, err = i.directorBackendClient(dc)
	case DIRECTORTYPE_CHASH:
		backend, err = i.directorBackendConsistentHash(dc)
	default:
		return nil, exception.System("Unexpected director type '%s' provided", dc.Type)
	}

	if err != nil {
		return nil, errors.WithStack(err)
	}
	return i.createBackendRequest(ctx, backend)
}

func (i *Interpreter) canDetermineBackend(dc *value.DirectorConfig) error {
	// Check healthy backends and quorum wight is not reached
	var healthyBackends int
	for _, v := range dc.Backends {
		if !v.Backend.Healthy.Load() {
			continue
		}
		healthyBackends++
	}
	// There is no healthy backend or healthyBackends is less than quorum
	if healthyBackends == 0 {
		return ErrAllBackendsFailed
	}
	if int((float64(healthyBackends)/float64(len(dc.Backends)))*100) < dc.Quorum {
		return ErrQuorumWeightNotReached
	}
	return nil
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
		// Check backens are enough healthy to determine
		if err := i.canDetermineBackend(dc); err != nil {
			// @SPEC: random director waits 10ms until retry backend detection
			time.Sleep(10 * time.Millisecond)
			continue
		}

		lottery := make([]int, 1000)
		var current int
		for index, v := range dc.Backends {
			// Skip if backend is unhealthy
			if !v.Backend.Healthy.Load() {
				continue
			}
			for i := 0; i < v.Weight; i++ {
				lottery[current] = index
				current++
			}
		}

		rand.New(rand.NewSource(time.Now().Unix()))
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

// Content director
// https://developer.fastly.com/reference/vcl/declarations/director/#content
func (i *Interpreter) directorBackendHash(dc *value.DirectorConfig) (*value.Backend, error) {
	// Hash should be calauclated based on request hash, means the same as cache object key
	hash := sha256.Sum256([]byte(i.ctx.RequestHash.Value))

	return i.getBackendByHash(dc, hash[:])
}

// Client director
// https://developer.fastly.com/reference/vcl/declarations/director/#client
func (i *Interpreter) directorBackendClient(dc *value.DirectorConfig) (*value.Backend, error) {
	var identity string
	if i.ctx.ClientIdentity != nil {
		identity = i.ctx.ClientIdentity.Value
	} else {
		identity = i.ctx.Request.RemoteAddr
		if idx := strings.LastIndex(identity, ":"); idx != -1 {
			identity = identity[:idx]
		}
	}
	hash := sha256.Sum256([]byte(identity))

	return i.getBackendByHash(dc, hash[:])
}

// Consistent Hashing director
// https://developer.fastly.com/reference/vcl/declarations/director/#consistent-hashing
func (i *Interpreter) directorBackendConsistentHash(dc *value.DirectorConfig) (*value.Backend, error) {
	if err := i.canDetermineBackend(dc); err != nil {
		return nil, err
	}

	var circles []uint32
	hashTable := make(map[uint32]*value.Backend)

	var healthyBackends int
	max := uint32(math.Pow(10, 4)) // max 10000
	// Put backends to the circles
	for _, v := range dc.Backends {
		if !v.Backend.Healthy.Load() {
			continue
		}
		healthyBackends++
		// typically loop three times in order to find suitable ring position
		for i := 0; i < 3; i++ {
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, dc.Seed)
			hash := sha256.New() // TODO: consider to user hash/fnv for getting performance guarantee
			hash.Write(buf)
			hash.Write([]byte(v.Backend.Value.Name.Value))
			hash.Write([]byte(fmt.Sprint(i)))
			h := hash.Sum(nil)
			num := binary.BigEndian.Uint32(h[:8]) % max
			hashTable[num] = v.Backend
			circles = append(circles, num)
		}
	}

	// Sort slice for binary search
	sort.Slice(circles, func(i, j int) bool {
		return circles[i] < circles[j]
	})

	var hashKey [32]byte
	switch dc.Key {
	case "object":
		hashKey = sha256.Sum256([]byte(i.ctx.RequestHash.Value))
	default: // same as client
		var identity string
		if i.ctx.ClientIdentity != nil {
			identity = i.ctx.ClientIdentity.Value
		} else {
			identity = i.ctx.Request.RemoteAddr
			if idx := strings.LastIndex(identity, ":"); idx != -1 {
				identity = identity[:idx]
			}
		}
		hashKey = sha256.Sum256([]byte(identity))
	}

	key := binary.BigEndian.Uint32(hashKey[:8]) % max
	index := sort.Search(len(circles), func(i int) bool {
		return circles[i] >= key
	})
	if index == len(circles) {
		index = 0
	}

	return hashTable[circles[index]], nil
}

func (i *Interpreter) getBackendByHash(dc *value.DirectorConfig, hash []byte) (*value.Backend, error) {
	if err := i.canDetermineBackend(dc); err != nil {
		return nil, err
	}

	var target *value.Backend
	for m := 4; m <= 16; m += 2 {
		max := uint64(math.Pow(10, float64(m)))
		num := binary.BigEndian.Uint64(hash[:8]) % max

		for _, v := range dc.Backends {
			if !v.Backend.Healthy.Load() {
				continue
			}
			bh := sha256.Sum256([]byte(v.Backend.Value.String()))
			b := binary.BigEndian.Uint64(bh[:8])
			if b%(max*10) >= num && b%(max*10) < num+max {
				target = v.Backend
				goto DETERMINED
			}
		}
	}
DETERMINED:

	// When target is not determined, use first healthy backend
	if target == nil {
		for _, v := range dc.Backends {
			if !v.Backend.Healthy.Load() {
				continue
			}
			return v.Backend, nil
		}
	}
	return target, nil
}
