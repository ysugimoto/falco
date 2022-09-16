package remote

import (
	_context "context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type FastlyApiFetcher struct {
	client *FastlyClient
	// Version can be set by multiple functions
	lock    sync.RWMutex
	version int64
	timeout time.Duration
}

func NewFastlyApiFetcher(serviceId, apiKey string, timeout time.Duration) *FastlyApiFetcher {
	return &FastlyApiFetcher{
		client:  NewFastlyClient(http.DefaultClient, serviceId, apiKey),
		version: -1,
		timeout: timeout,
	}
}

func (f *FastlyApiFetcher) Backends() ([]*Backend, error) {
	ctx, timeout := _context.WithTimeout(_context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	return f.client.ListBackends(ctx, version)
}
func (f *FastlyApiFetcher) Dictionaries() ([]*EdgeDictionary, error) {
	c, timeout := _context.WithTimeout(_context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	return f.client.ListEdgeDictionaries(c, version)
}
func (f *FastlyApiFetcher) Acls() ([]*AccessControl, error) {
	c, timeout := _context.WithTimeout(_context.Background(), f.timeout)
	defer timeout()
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
