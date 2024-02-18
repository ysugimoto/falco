package http

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/ysugimoto/falco/interpreter/value"
)

const (
	DIRECTORTYPE_RANDOM   = "random"
	DIRECTORTYPE_FALLBACK = "fallback"
	DIRECTORTYPE_HASH     = "hash"
	DIRECTORTYPE_CLIENT   = "client"
	DIRECTORTYPE_CHASH    = "chash"
	DIRECTORTYPE_SHIELD   = "shield"
)

var ValidDirectorTypes = map[string]struct{}{
	DIRECTORTYPE_RANDOM:   {},
	DIRECTORTYPE_FALLBACK: {},
	DIRECTORTYPE_HASH:     {},
	DIRECTORTYPE_CLIENT:   {},
	DIRECTORTYPE_CHASH:    {},
	DIRECTORTYPE_SHIELD:   {},
}

var (
	ErrQuorumWeightNotReached = errors.New("Quorum weight not reached")
	ErrAllBackendsFailed      = errors.New("All backend failed")
)

type DirectorBackend struct {
	Backend *value.Backend
	Id      string
	Weight  int
}

// Injectable identity seeds for backend election
type DirectorIdentity struct {
	RequestHash    string
	ClientIdentity string
}

// Director implementation - includes backend election methods
type Director struct {
	Type          string // director type
	Name          string // director name
	Quorum        int    // only exists on random, hash, client and chash
	Retries       int    // only exists on random
	Key           string // only exists on chash
	Seed          uint32 // only exists on chash
	VNodesPerNode int    // only exists on chash
	Backends      []*DirectorBackend
}

// Virtual interface implementation, used for value package
func (d *Director) Director() string {
	return d.Name
}

// Random director
// https://developer.fastly.com/reference/vcl/declarations/director/#random
func (d *Director) Random() (*value.Backend, error) {
	// For random director, .retries value should use backend count as default.
	maxRetry := d.Retries
	if maxRetry == 0 {
		maxRetry = len(d.Backends)
	}

	for retry := 0; retry < maxRetry; retry++ {
		// Check backends are enough healthy to determine
		if err := d.canDetermineBackend(); err != nil {
			// @SPEC: random director waits 10ms until retry backend detection
			time.Sleep(10 * time.Millisecond)
			continue
		}

		lottery := make([]int, 1000)
		var current int
		for index, v := range d.Backends {
			// Skip if backend is unhealthy
			if !v.Backend.Healthy.Load() {
				continue
			}
			for i := 0; i < v.Weight; i++ {
				lottery[current] = index
				current++
			}
		}

		lottery = lottery[0:current]
		item := d.Backends[lottery[rand.Intn(current)]]

		return item.Backend, nil
	}

	return nil, ErrQuorumWeightNotReached
}

// Fallback director
// https://developer.fastly.com/reference/vcl/declarations/director/#fallback
func (d *Director) Fallback() (*value.Backend, error) {
	for _, v := range d.Backends {
		if v.Backend.Healthy.Load() {
			return v.Backend, nil
		}
	}

	return nil, ErrAllBackendsFailed
}

// Content director
// https://developer.fastly.com/reference/vcl/declarations/director/#content
func (d *Director) Hash(ident DirectorIdentity) (*value.Backend, error) {
	// Hash should be calauclated based on request hash, means the same as cache object key
	hash := sha256.Sum256([]byte(ident.RequestHash))

	return d.getBackendByHash(hash[:])
}

// Client director
// https://developer.fastly.com/reference/vcl/declarations/director/#client
func (d *Director) Client(ident DirectorIdentity) (*value.Backend, error) {
	hash := sha256.Sum256([]byte(ident.ClientIdentity))

	return d.getBackendByHash(hash[:])
}

// Consistent Hashing director
// https://developer.fastly.com/reference/vcl/declarations/director/#consistent-hashing
func (d *Director) ConsistentHash(ident DirectorIdentity) (*value.Backend, error) {
	if err := d.canDetermineBackend(); err != nil {
		return nil, err
	}

	var circles []uint32
	hashTable := make(map[uint32]*value.Backend)

	var healthyBackends int
	max := uint32(math.Pow(10, 4)) // max 10000
	// Put backends to the circles
	for _, v := range d.Backends {
		if !v.Backend.Healthy.Load() {
			continue
		}
		healthyBackends++
		// typically loop three times in order to find suitable ring position
		for i := 0; i < 3; i++ {
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, d.Seed)
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
	switch d.Key {
	case "object":
		hashKey = sha256.Sum256([]byte(ident.RequestHash))
	default: // same as client
		hashKey = sha256.Sum256([]byte(ident.ClientIdentity))
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

func (d *Director) getBackendByHash(hash []byte) (*value.Backend, error) {
	if err := d.canDetermineBackend(); err != nil {
		return nil, err
	}

	var target *value.Backend
	for m := 4; m <= 16; m += 2 {
		max := uint64(math.Pow(10, float64(m)))
		num := binary.BigEndian.Uint64(hash[:8]) % max

		for _, v := range d.Backends {
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
		for _, v := range d.Backends {
			if !v.Backend.Healthy.Load() {
				continue
			}
			return v.Backend, nil
		}
	}
	return target, nil
}

func (d *Director) canDetermineBackend() error {
	// Check healthy backends and quorum wight is not reached
	var healthyBackends int
	for _, v := range d.Backends {
		if !v.Backend.Healthy.Load() {
			continue
		}
		healthyBackends++
	}
	// There is no healthy backend or healthyBackends is less than quorum
	if healthyBackends == 0 {
		return ErrAllBackendsFailed
	}
	if int((float64(healthyBackends)/float64(len(d.Backends)))*100) < d.Quorum {
		return ErrQuorumWeightNotReached
	}
	return nil
}
