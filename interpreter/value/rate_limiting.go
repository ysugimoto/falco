package value

import (
	"math"
	"sync"
	"time"

	"github.com/ysugimoto/falco/ast"
)

// rateEntry represents single access entry for a client
type rateEntry struct {
	Count     int64
	Timestamp int64 // unix time millisecond
}

func calculateBucketWithTime(now int64, entries []rateEntry, window time.Duration) int64 {
	currentEpoch := now / 10000
	numSlots := int64(window.Seconds()) / 10

	var bucket int64
	for _, entry := range entries {
		entryEpoch := entry.Timestamp / 10000
		if entryEpoch > currentEpoch-numSlots && entryEpoch <= currentEpoch {
			bucket += entry.Count
		}
	}
	return bucket
}

func calculateRateWithTime(now int64, entries []rateEntry, window time.Duration) float64 {
	windowSec := int64(window.Seconds())
	cutoff := now - window.Milliseconds()
	var total int64
	for _, entry := range entries {
		if entry.Timestamp > cutoff {
			total += entry.Count
		}
	}
	if total == 0 {
		return 0
	}
	return math.Floor(float64(total) / float64(windowSec))
}

func calculateBucket(entries []rateEntry, window time.Duration) int64 {
	return calculateBucketWithTime(time.Now().UnixMilli(), entries, window)
}

func calculateRate(entries []rateEntry, window time.Duration) float64 {
	return calculateRateWithTime(time.Now().UnixMilli(), entries, window)
}

// Ratecounter represents ratecounter declaration with holding client map
type Ratecounter struct {
	Decl *ast.RatecounterDeclaration

	// Ratecounter's client count is native map, not a sync.Map.
	// This means we won't think about race coundition, allows unexpected behavior under the concurrency.
	Clients map[string][]rateEntry

	// Ratecounter related value like ratecounter.{NAME}.bucket.10s could be accessible after some ratecounter related functions have been called:
	// - `ratelimitatelimit.check_rate`
	// - `ratelimit.check_rates`
	// - `ratelimit.ratecounter_increment`
	// This field managed whether either of above functions is called
	IsAccessible bool
}

func NewRatecounter(decl *ast.RatecounterDeclaration) *Ratecounter {
	return &Ratecounter{
		Decl:    decl,
		Clients: make(map[string][]rateEntry),
	}
}

// Increment() increments access entry manually.
// This function should be called via ratelimit.ratecounter_increment() VCL function
func (r *Ratecounter) Increment(entry string, delta int64) {
	if _, ok := r.Clients[entry]; !ok {
		r.Clients[entry] = []rateEntry{}
	}
	r.Clients[entry] = append(r.Clients[entry], rateEntry{
		Count:     delta,
		Timestamp: time.Now().UnixMilli(),
	})
	r.IsAccessible = true
}

// Bucket() returns access count for provided window.
// This function will be called for specific variables like ratecounter.{NAME}.bucket.10s
func (r *Ratecounter) Bucket(entry string, window time.Duration) int64 {
	if !r.IsAccessible {
		return 0
	}
	entries, ok := r.Clients[entry]
	if !ok {
		return 0
	}
	return calculateBucket(entries, window)
}

// Rate() returns access rate for provided window.
// This function will be called for specific variables like ratecounter.{NAME}.rate.1s
func (r *Ratecounter) Rate(entry string, window time.Duration) float64 {
	if !r.IsAccessible {
		return 0
	}
	entries, ok := r.Clients[entry]
	if !ok {
		return 0
	}
	return calculateRate(entries, window)
}

// Penaltybox implementation
// holds client IP and expiration, and check client whether burned or not
type Penaltybox struct {
	Decl    *ast.PenaltyboxDeclaration
	Clients sync.Map
}

func NewPenaltybox(decl *ast.PenaltyboxDeclaration) *Penaltybox {
	return &Penaltybox{
		Decl:    decl,
		Clients: sync.Map{},
	}
}

// Add() is operation of ratelimit.penaltybox_add() function
func (p *Penaltybox) Add(entry string, ttl time.Duration) {
	p.Clients.Store(entry, time.Now().Add(ttl))
}

// Has() is operation of ratelimit.penaltybox_has() function
func (p *Penaltybox) Has(entry string) bool {
	// Load the entry
	v, ok := p.Clients.Load(entry)
	if !ok {
		return false
	}

	// Value type must be time.Time, otherwise delete entry
	expire, ok := v.(time.Time)
	if !ok {
		p.Clients.Delete(entry)
		return false
	}
	// Check expiration
	if expire.Before(time.Now()) {
		p.Clients.Delete(entry)
		return false
	}
	return true
}
