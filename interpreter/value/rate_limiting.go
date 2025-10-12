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
	Timestamp int64 // unix time second
}

func calculateBucketWithTime(now int64, entries []rateEntry, window time.Duration) int64 {
	var from, to int64

	// Calculate window range timestamps.
	// Fastly says the window is not continuous, the window has reset for each 0 second unit,
	// and bucket always contains the bucket range of 0 second unit.
	// see https://www.fastly.com/documentation/guides/concepts/rate-limiting/#estimated-bucket-counts
	mod := now % 10
	to = now - mod
	from = to - int64(window.Seconds())

	var bucket int64
	for _, entry := range entries {
		if from <= entry.Timestamp && to+10 > entry.Timestamp {
			bucket += entry.Count
		}
	}
	return bucket
}

func calculateRateWithTime(now int64, entries []rateEntry, window time.Duration) float64 {
	var from, to int64

	mod := now % 10
	to = now - mod + 1
	from = to - int64(window.Seconds())

	var bucket int64
	for _, entry := range entries {
		if from <= entry.Timestamp && to > entry.Timestamp {
			bucket += entry.Count
		}
	}
	if bucket == 0 {
		return 0
	}
	return math.Floor(float64(bucket) / window.Seconds())
}

func calculateBucket(entries []rateEntry, window time.Duration) int64 {
	return calculateBucketWithTime(time.Now().Unix(), entries, window)
}

func calculateRate(entries []rateEntry, window time.Duration) float64 {
	return calculateRateWithTime(time.Now().Unix(), entries, window)
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
func (r *Ratecounter) Increment(entry string, delta int64, window time.Duration) {
	if _, ok := r.Clients[entry]; !ok {
		r.Clients[entry] = []rateEntry{}
	}
	r.Clients[entry] = append(r.Clients[entry], rateEntry{
		Count:     delta,
		Timestamp: time.Now().Add(-window).Unix(),
	})
	// Set accessible
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
