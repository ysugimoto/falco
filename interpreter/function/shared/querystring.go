package shared

import (
	"net/url"
	"sort"
	"strings"
)

// The functions in this file implement Fastly querystring behavior
// See: https://www.fastly.com/documentation/reference/vcl/functions/query-string/

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

func joinPair(lh, rh, sep string) string {
	return lh + sep + rh
}

// Returns the given URL with the given parameter name set to the given value,
// replacing the original value and removing any duplicates. If the parameter
// is not present in the query string, the parameter will be appended with the
// given value to the end of the query string. The parameter name and value
// will be URL-encoded when set in the query string.
//
// See: https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-set/
func QueryStringSet(urlStr, name, value string) string {
	escapedKey := queryEscape(name)
	escapedVal := queryEscape(value)
	pairToAdd := joinPair(escapedKey, escapedVal, "=")
	if path, query := splitPair(urlStr, "?"); query != nil {
		kvPairs := strings.Split(*query, "&")
		updated := false
		updatedQuery := make([]string, 0)
		for _, pair := range kvPairs {
			k, _ := splitPair(pair, "=")
			switch {
			case k != escapedKey:
				updatedQuery = append(updatedQuery, pair)
			case !updated:
				updatedQuery = append(updatedQuery, pairToAdd)
				updated = true
			default:
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

// Returns the given URL with the given parameter name and value appended to
// the end of the query string. The parameter name and value will be
// URL-encoded when added to the query string.
//
// See: https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-add/
func QueryStringAdd(urlStr, name, value string) string {
	k := queryEscape(name)
	v := queryEscape(value)
	pair := joinPair(k, v, "=")
	if path, query := splitPair(urlStr, "?"); query != nil {
		*query += "&" + pair
		return joinPair(path, *query, "?")
	}
	return joinPair(urlStr, pair, "?")
}

// Returns a value associated with the name in the query component of an URL.
//
// If the query component does not contain a value associated with name, then
// querystring.get returns a not set value. For example,
// querystring.get("/?a=1&b=2&c=3", "d") is a not set value.
//
// If a query parameter associated with name is found but the value is absent,
// then querystring.get returns the string "". For example,
// querystring.get("/?a=1&b=&c=3", "b") is "".
//
// If multiple query parameters of the same name are present in the query
// component, then querystring.get returns the first value associated with name.
// For example, querystring.get("/?a=1&b=2&c=3&b=4&d=5", "b") is "2".
//
// If the URL does not include a query component, then querystring.get returns
// a not set value. For example, querystring.get("/", "a") is a not set value.
//
// If querystring.get is called with not set or empty string arguments, then
// it returns a not set value. For example, querystring.get("", "") is a not
// set value.
//
// See: https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-get/
func QueryStringGet(urlStr, name string) *string {
	escapedKey := queryEscape(name)
	if _, query := splitPair(urlStr, "?"); query != nil {
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

// Returns the given URL without empty parameters. Parameters are considered empty
// when their names are empty. Effectively, this strips a malformed query string
// of superfluous separators, such as a trailing ? or extra ampersands:
//
//	/path?name=value&&=value-only&name-only becomes /path?name=value&name-only
//	/path? becomes /path
//
// See: https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-clean/
func QueryStringClean(urlStr string) string {
	if path, query := splitPair(urlStr, "?"); query != nil {
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
	return urlStr
}

// Returns the given URL with only those parameters for which filter function
// returns true.
//
// See:
//   - https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-filter/
//   - https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-filter-except/
//   - https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-globfilter/
//   - https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-globfilter-except/
//   - https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-regfilter/
//   - https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-regfilter-except/
func QueryStringFilter(urlStr string, filter func(name string) bool) string {
	if path, query := splitPair(urlStr, "?"); query != nil {
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
	return urlStr
}

type SortMode string

const (
	SortAsc  SortMode = "asc"
	SortDesc SortMode = "desc"
)

// Returns the given URL with its query string sorted.
// For example, querystring.sort("/foo?b=1&a=2&c=3", SortAsc);
// returns "/foo?a=2&b=1&c=3".
//
// See: https://www.fastly.com/documentation/reference/vcl/functions/query-string/querystring-sort/
func QueryStringSort(urlStr string, mode SortMode) string {
	if path, query := splitPair(urlStr, "?"); query != nil {
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
	return urlStr
}
