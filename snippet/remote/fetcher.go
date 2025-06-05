package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/snippet"
)

type FastlyApiFetcher struct {
	client *FastlyClient
	// Version can be set by multiple functions
	lock      sync.RWMutex
	version   int64
	serviceId string
	timeout   time.Duration
}

func NewFastlyApiFetcher(serviceId, apiKey string, timeout time.Duration) snippet.Fetcher {
	return &FastlyApiFetcher{
		client:    NewFastlyClient(http.DefaultClient, serviceId, apiKey),
		serviceId: serviceId,
		version:   -1,
		timeout:   timeout,
	}
}

func (f *FastlyApiFetcher) getVersion(c context.Context) (int64, error) {
	defer f.lock.Unlock()
	f.lock.Lock()

	if f.version != -1 {
		return f.version, nil
	}
	v, err := f.client.LatestVersion(c)
	if err != nil {
		return -1, errors.WithStack(err)
	}
	f.version = v
	return v, nil
}

func (f *FastlyApiFetcher) LookupCache(refresh bool) *snippet.Snippets {
	ctx, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(ctx)
	if err != nil {
		return nil
	}

	cacheFile, err := getOrCreateCacheFile(f.serviceId, version)
	if err != nil {
		return nil
	}

	// If refresh flag is true, purge cache
	if refresh {
		os.Remove(cacheFile) // nolint:errcheck
		return nil
	}

	fp, err := os.Open(cacheFile)
	if err != nil {
		return nil
	}
	defer fp.Close()

	snippets := &snippet.Snippets{}
	if err := json.NewDecoder(fp).Decode(snippets); err != nil {
		return nil
	}

	return snippets
}

func (f *FastlyApiFetcher) WriteCache(snip *snippet.Snippets) {
	ctx, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(ctx)
	if err != nil {
		return
	}

	cacheFile, err := getOrCreateCacheFile(f.serviceId, version)
	if err != nil {
		return
	}

	fp, err := os.OpenFile(cacheFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return
	}
	defer fp.Close()

	json.NewEncoder(fp).Encode(snip) // nolint:errcheck
}

func (f *FastlyApiFetcher) ResponseObjects() ([]*snippet.ResponseObject, error) {
	ctx, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	responseObjects, err := f.client.ListResponseObjects(ctx, version)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := make([]*snippet.ResponseObject, len(responseObjects))
	for i, ro := range responseObjects {
		status, err := strconv.ParseInt(ro.Status, 10, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		r[i] = &snippet.ResponseObject{
			Name:             ro.Name,
			Status:           status,
			ContentType:      ro.ContentType,
			RequestCondition: ro.RequestCondition,
			CacheCondition:   ro.CacheCondition,
			Content:          ro.Content,
			Response:         ro.Response,
		}
	}
	return r, nil
}

func (f *FastlyApiFetcher) Headers() ([]*snippet.Header, error) {
	ctx, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	headers, err := f.client.ListHeaders(ctx, version)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := make([]*snippet.Header, len(headers))
	for i, h := range headers {
		priority, err := strconv.ParseInt(h.Priority, 10, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		var condition *string
		switch h.Type {
		case "request":
			condition = h.RequestCondition
		case "cache":
			condition = h.CacheCondition
		case "response":
			condition = h.ResponseCondition
		}

		r[i] = &snippet.Header{
			Type:         snippet.Phase(strings.ToUpper(h.Type)),
			Action:       snippet.Action(h.Action),
			Name:         h.Name,
			IgnoreIfSet:  h.IgnoreIfSet == "1",
			Condition:    condition,
			Priority:     priority,
			Source:       h.Source,
			Destination:  h.Destination,
			Regex:        h.Regex,
			Substitution: h.Substitution,
		}
	}
	return r, nil
}

func (f *FastlyApiFetcher) Conditions() ([]*snippet.Condition, error) {
	ctx, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	conditions, err := f.client.ListConditions(ctx, version)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := make([]*snippet.Condition, len(conditions))
	for i, cond := range conditions {
		priority, err := strconv.ParseInt(cond.Priority, 10, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		r[i] = &snippet.Condition{
			Name:      cond.Name,
			Statement: cond.Statement,
			Type:      snippet.Phase(cond.Type),
			Priority:  priority,
		}
	}
	return r, nil
}

func (f *FastlyApiFetcher) Backends() ([]*snippet.Backend, error) {
	ctx, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	backends, err := f.client.ListBackends(ctx, version)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := make([]*snippet.Backend, len(backends))
	for i, b := range backends {
		r[i] = &snippet.Backend{
			Name:    b.Name,
			Shield:  b.Shield,
			Address: b.Address,
		}
	}
	return r, nil
}

func (f *FastlyApiFetcher) Dictionaries() ([]*snippet.Dictionary, error) {
	c, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	dictionaries, err := f.client.ListEdgeDictionaries(c, version)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := make([]*snippet.Dictionary, len(dictionaries))
	for i, dict := range dictionaries {
		items := make([]*snippet.DictionaryItem, len(dict.Items))
		for j, item := range dict.Items {
			items[j] = &snippet.DictionaryItem{
				Key:   item.Key,
				Value: item.Value,
			}
		}
		r[i] = &snippet.Dictionary{
			Name:  dict.Name,
			Items: items,
		}
	}
	return r, nil
}

func (f *FastlyApiFetcher) Acls() ([]*snippet.Acl, error) {
	c, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	acls, err := f.client.ListAccessControlLists(c, version)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := make([]*snippet.Acl, len(acls))
	for i, a := range acls {
		entries := make([]*snippet.AclEntry, len(a.Entries))
		for j, v := range a.Entries {
			entries[j] = &snippet.AclEntry{
				Ip:      v.Ip,
				Negated: v.Negated == "1",
				Subnet:  v.Subnet,
				Comment: v.Comment,
			}
		}
		r[i] = &snippet.Acl{
			Name:    a.Name,
			Entries: entries,
		}
	}
	return r, nil
}

func (f *FastlyApiFetcher) Directors() ([]*snippet.Director, error) {
	c, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	directors, err := f.client.ListDirectors(c, version)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := make([]*snippet.Director, len(directors))
	for i, d := range directors {
		r[i] = &snippet.Director{
			Type:     int(d.Type),
			Name:     d.Name,
			Backends: d.Backends,
			Retries:  d.Retries,
			Quorum:   d.Quorum,
		}
	}
	return r, nil
}

func (f *FastlyApiFetcher) Snippets() ([]*snippet.VCLSnippet, error) {
	c, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()

	version, err := f.getVersion(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	snippets, err := f.client.ListSnippets(c, version)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := make([]*snippet.VCLSnippet, len(snippets))
	for i, v := range snippets {
		p, err := strconv.ParseInt(v.Priority, 10, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		r[i] = &snippet.VCLSnippet{
			Name:     v.Name,
			Type:     v.Type,
			Content:  *v.Content,
			Priority: p,
		}
	}
	return r, nil
}

func (f *FastlyApiFetcher) LoggingEndpoints() ([]string, error) {
	c, timeout := context.WithTimeout(context.Background(), f.timeout)
	defer timeout()

	version, err := f.getVersion(c)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return f.client.ListLoggingEndpoints(c, version)
}

var _ snippet.Fetcher = (*FastlyApiFetcher)(nil)
