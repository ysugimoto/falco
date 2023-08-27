package interpreter

import (
	"fmt"
	"strings"
	"time"

	"net/http"
)

type CacheItem struct {
	Response  *http.Response
	Expires   time.Time
	EntryTime time.Time
	Hits      int
}

type Cache map[string]*CacheItem

func (c Cache) Set(hash string, item *CacheItem) {
	c[hash] = item
}

func (c Cache) Get(hash string) *http.Response {
	v, ok := c[hash]
	if !ok {
		return nil
	} else if time.Now().After(v.Expires) {
		delete(c, hash)
		return nil
	}

	// If cache object exists, set cache related header
	// Increment cache hits
	v.Hits++
	v.Response.Header.Set("X-Cache", "HIT")
	v.Response.Header.Set("X-Cache-Hits", fmt.Sprint(v.Hits))
	v.Response.Header.Set("Age", fmt.Sprintf("%.0f", time.Since(v.EntryTime).Seconds()))
	return v.Response
}

var cache = Cache{}

var unCacheableStatusCodes = []int{200, 203, 300, 301, 302, 404, 410}
var expiresValueLayout = "Mon, 02 Jan 2006 15:04:05 MST"

// Fastly follows its own cache freshness rules
// see: https://developer.fastly.com/learning/concepts/cache-freshness/
func (i *Interpreter) isCacheableResponse(resp *http.Response) bool {
	for _, v := range unCacheableStatusCodes {
		if v == resp.StatusCode {
			return true
		}
	}
	return false
}

func (i *Interpreter) determineCacheTTL(resp *http.Response) time.Duration {
	if v := resp.Header.Get("Surrogate-Control"); v != "" {
		if strings.HasPrefix(v, "max-age=") {
			if dur, err := time.ParseDuration(strings.TrimPrefix(v, "max-age=") + "s"); err == nil {
				return dur
			}
		}
	}
	if v := resp.Header.Get("Cache-Control"); v != "" {
		if strings.HasPrefix(v, "s-maxage=") {
			if dur, err := time.ParseDuration(strings.TrimPrefix(v, "s-maxage=") + "s"); err == nil {
				return dur
			}
		}
		if strings.HasPrefix(v, "max-age=") {
			if dur, err := time.ParseDuration(strings.TrimPrefix(v, "max-age=") + "s"); err == nil {
				return dur
			}
		}
	}
	if v := resp.Header.Get("Expires"); v != "" {
		if d, err := time.Parse(expiresValueLayout, v); err == nil {
			return time.Until(d)
		}
	}
	return time.Duration(2 * time.Minute)
}

// Create cache datacenter string
// This value is not important but create some string that we want to serve
func createCacheDCString() string {
	return "cache-localsimulator-FALCO"
}
