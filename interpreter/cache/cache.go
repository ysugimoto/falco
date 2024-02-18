// Falco's interpreter cacheing is simply in-memory
package cache

import (
	"sync"
	"time"

	flchttp "github.com/ysugimoto/falco/interpreter/http"
)

const (
	LocalDatacenterString = "cache-localsimulator-FALCO"
)

type CacheItem struct {
	Response  *flchttp.Response
	Expires   time.Time
	EntryTime time.Time
	Hits      int
	LastUsed  time.Duration

	// private
	requestedTime time.Time
}

func (i *CacheItem) Update(d time.Duration) {
	i.Expires = i.EntryTime.Add(d)
}

type Cache struct {
	storage sync.Map
}

func New() *Cache {
	return &Cache{}
}

func (c *Cache) Set(hash string, item *CacheItem) {
	item.requestedTime = item.EntryTime
	c.storage.Store(hash, item)
}

func (c *Cache) Get(hash string) *CacheItem {
	// Load and cast to *CacheItem
	v, ok := c.storage.Load(hash)
	if !ok {
		return nil
	}
	item, ok := v.(*CacheItem)
	if !ok {
		return nil
	}
	// Check expiration
	if time.Now().After(item.Expires) {
		c.storage.Delete(hash)
		return nil
	}

	// Update cache state - increment Hit count, update last used time
	item.Hits++
	item.LastUsed = time.Since(item.requestedTime)
	item.requestedTime = time.Now()
	return item
}

// Fastly follows its own cache freshness rules
// see: https://developer.fastly.com/learning/concepts/cache-freshness/
var unCacheableStatusCodes = []int{200, 203, 300, 301, 302, 404, 410}

func IsCacheableStatusCode(statusCode int) bool {
	for _, v := range unCacheableStatusCodes {
		if v == statusCode {
			return true
		}
	}
	return false
}
