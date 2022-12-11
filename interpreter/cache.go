package interpreter

import (
	"github.com/ysugimoto/falco/interpreter/variable"
	"time"
)

type CacheItem struct {
	Vars    variable.Variable
	Expires time.Time
}

type Cache map[string]CacheItem

func (c Cache) Set(hash string, item CacheItem) {
	c[hash] = item
}

func (c Cache) Get(hash string) *CacheItem {
	if v, ok := c[hash]; !ok {
		return nil
	} else if time.Now().After(v.Expires) {
		delete(c, hash)
		return nil
	} else {
		return &v
	}
}

var cache = Cache{}
