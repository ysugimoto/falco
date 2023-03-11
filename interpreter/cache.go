package interpreter

import (
	"strings"
	"time"

	"net/http"
)

type CacheItem struct {
	Response *http.Response
	Expires  time.Time
}

type Cache map[string]CacheItem

func (c Cache) Set(hash string, item CacheItem) {
	c[hash] = item
}

func (c Cache) Get(hash string) *http.Response {
	if v, ok := c[hash]; !ok {
		return nil
	} else if time.Now().After(v.Expires) {
		delete(c, hash)
		return nil
	} else {
		return v.Response
	}
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
