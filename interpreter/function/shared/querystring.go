package shared

import (
	"net/url"
	"sort"
	"strings"
)

func queryEscape(s string) string {
	escaped := url.QueryEscape(s)
	return strings.ReplaceAll(escaped, "+", "%20")
}

func splitPair(pair, sep string) (string, *string) {
	index := strings.Index(pair, sep)
	if index < 0 {
		return pair, nil
	} else {
		rh := pair[index+1:]
		return pair[0:index], &rh
	}
}

func joinPair(lh string, rh string, sep string) string {
	return lh + sep + rh
}

func QueryStringSet(qs, key, val string) string {
	escapedKey := queryEscape(key)
	escapedVal := queryEscape(val)
	pairToAdd := joinPair(escapedKey, escapedVal, "=")
	if path, query := splitPair(qs, "?"); query != nil {
		kvPairs := strings.Split(*query, "&")
		updated := false
		updatedQuery := make([]string, 0)
		for _, pair := range kvPairs {
			k, _ := splitPair(pair, "=")
			if k != escapedKey {
				updatedQuery = append(updatedQuery, pair)
			} else if !updated {
				updatedQuery = append(updatedQuery, pairToAdd)
				updated = true
			} else {
				// skip over repeated occurrences of updated query param.
			}
		}
		if !updated {
			updatedQuery = append(updatedQuery, pairToAdd)
		}
		queryString := strings.Join(updatedQuery, "&")
		return joinPair(path, queryString, "?")
	} else {
		return joinPair(path, pairToAdd, "?")
	}
}

func QueryStringAdd(qs, key, val string) string {
	k := queryEscape(key)
	v := queryEscape(val)
	pair := joinPair(k, v, "=")
	if path, query := splitPair(qs, "?"); query != nil {
		*query += "&" + pair
		return joinPair(path, *query, "?")
	}
	return joinPair(qs, pair, "?")
}

func QueryStringGet(qs, key string) *string {
	escapedKey := queryEscape(key)
	if _, query := splitPair(qs, "?"); query != nil {
		pairs := strings.Split(*query, "&")
		for _, pair := range pairs {
			k, v := splitPair(pair, "=")
			if k == escapedKey {
				return v
			}
		}
	}
	return nil
}

func QueryStringClean(qs string) string {
	if path, query := splitPair(qs, "?"); query != nil {
		if *query == "" {
			return path // Special case. If there is '?' but no query, fastly removes '?'
		}
		cleaned := make([]string, 0)
		pairs := strings.Split(*query, "&")
		for _, pair := range pairs {
			key, _ := splitPair(pair, "=")
			if key != "" {
				cleaned = append(cleaned, pair)
			}
		}
		cleanedQuery := strings.Join(cleaned, "&")
		return joinPair(path, cleanedQuery, "?")
	}
	return qs
}

func QueryStringFilter(qs string, filter func(name string) bool) string {
	if path, query := splitPair(qs, "?"); query != nil {
		pairs := strings.Split(*query, "&")
		filtered := make([]string, 0)
		for _, pair := range pairs {
			k, _ := splitPair(pair, "=")
			if filter(k) {
				filtered = append(filtered, pair)
			}
		}
		if len(filtered) == 0 {
			return path
		}
		filteredQuery := strings.Join(filtered, "&")
		return joinPair(path, filteredQuery, "?")
	}
	return qs
}

type SortMode string

const (
	SortAsc  SortMode = "asc"
	SortDesc SortMode = "desc"
)

func QueryStringSort(qs string, mode SortMode) string {
	if path, query := splitPair(qs, "?"); query != nil {
		pairs := strings.Split(*query, "&")
		sort.Slice(pairs, func(i, j int) bool {
			v := pairs[i] > pairs[j]
			if mode == SortAsc {
				return !v
			}
			return v
		})
		return joinPair(path, strings.Join(pairs, "&"), "?")
	}
	return qs
}
