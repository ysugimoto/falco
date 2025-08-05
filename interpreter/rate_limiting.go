package interpreter

import (
	"sync"
	"time"

	"github.com/ysugimoto/falco/ast"
)

// RateEntry represents single access entry for a client
type RateEntry struct {
	Count     int64
	CreatedAt time.Time
}

func newRateEntry(delta int64) *RateEntry {
	return &RateEntry{
		Count:     delta,
		CreatedAt: time.Now(),
	}
}

// Ratecount represents rate count status for a client
type Ratecount struct {
	Entries    []*RateEntry
	Increments []*RateEntry
}

// count() increments access count with 1, means single client access
func (r *Ratecount) count() {
	r.Entries = append(r.Entries, newRateEntry(1))
}

// increment() increments manual client access count.
func (r *Ratecount) increment(delta int64) {
	r.Increments = append(r.Increments, newRateEntry(delta))
}

// sweep() sweeps expired access entries
func (r *Ratecount) sweep() {
	now := time.Now()

	var index int
	for i := range r.Entries {
		if now.Sub(r.Entries[i].CreatedAt) > time.Minute {
			continue
		}
		index = i
		break
	}
	r.Entries = r.Entries[index:]
}

// bucket() calculates access count for provided window
func (r *Ratecount) bucket(window time.Duration) int64 {
	var bucket int64

	now := time.Now()
	for i := range r.Entries {
		if now.Sub(r.Entries[i].CreatedAt) > window {
			continue
		}
		bucket += r.Entries[i].Count
	}

	return bucket
}

// bucket() calculates access rate for provided window
func (r *Ratecount) rate(window time.Duration) float64 {
	bucket := r.bucket(window)
	if bucket == 0 {
		return 0
	}
	return float64(bucket) / float64(window)
}

// Ratecounter represents ratecounter declaration with holding client map
type Ratecounter struct {
	Decl *ast.RatecounterDeclaration
	// Ratecounter's client count is native map, not a sync.Map.
	// This means we won't think about race coundition, allows unexpected behavior under the concurrency.
	Clients map[string]*Ratecount
}

// sweep() cleans up expired entries for each clients
func (r *Ratecounter) sweep() {
	for _, c := range r.Clients {
		c.sweep()
	}
}

// Count() increments single access entry
func (r *Ratecounter) Count(entry string) {
	if _, ok := r.Clients[entry]; !ok {
		r.Clients[entry] = &Ratecount{}
	}
	r.Clients[entry].count()
}

// Increment() increments access entry manually.
// This function should be called via ratelimit.ratecounter_increment() VCL function
func (r *Ratecounter) Increment(entry string, delta int64) {
	if _, ok := r.Clients[entry]; !ok {
		r.Clients[entry] = &Ratecount{}
	}
	r.Clients[entry].increment(delta)
}

// Bucket() returns access count for provided window.
// This function will be called for specific variables like ratecounter.{NAME}.bucket.10s
func (r *Ratecounter) Bucket(entry string, window time.Duration) int64 {
	if _, ok := r.Clients[entry]; !ok {
		r.Clients[entry] = &Ratecount{}
	}

	return r.Clients[entry].bucket(window)
}

// This function will be called for specific variables like ratecounter.{NAME}.rate.1s
func (r *Ratecounter) Rate(entry string, window time.Duration) float64 {
	if _, ok := r.Clients[entry]; !ok {
		r.Clients[entry] = &Ratecount{}
	}

	return r.Clients[entry].rate(window)
}

// Penaltybox implementation
// holds client IP and expiration, and check client whether burned or not
type Penaltybox struct {
	Decl    *ast.PenaltyboxDeclaration
	Clients sync.Map
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
