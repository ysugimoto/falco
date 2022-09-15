package remote

import (
	_context "context"
	"fmt"
	"net/http"
	"sync"
)

type FastlyApiFetcher struct {
	client *FastlyClient
	// Version can be set by multiple functions
	lock    sync.RWMutex
	version int64
}

func NewFastlyApiFetcher(serviceId, apiKey string) *FastlyApiFetcher {
	return &FastlyApiFetcher{
		client:  NewFastlyClient(http.DefaultClient, serviceId, apiKey),
		version: -1,
	}
}

func (f *FastlyApiFetcher) Backends(c _context.Context) ([]*Backend, error) {
	version, err := f.getVersion(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	return f.client.ListBackends(c, version)
}
func (f *FastlyApiFetcher) Dictionaries(c _context.Context) ([]*EdgeDictionary, error) {
	version, err := f.getVersion(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	return f.client.ListEdgeDictionaries(c, version)
}
func (f *FastlyApiFetcher) Acls(c _context.Context) ([]*AccessControl, error) {
	version, err := f.getVersion(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	return f.client.ListAccessControlLists(c, version)
}

func (f *FastlyApiFetcher) getVersion(c _context.Context) (int64, error) {
	defer f.lock.Unlock()
	f.lock.Lock()
	if f.version != -1 {
		return f.version, nil
	}
	v, err := f.client.LatestVersion(c)
	if err != nil {
		return -1, err
	}
	f.version = v
	return v, nil
}
