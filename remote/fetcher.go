package remote

import (
	"context"
	_context "context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ysugimoto/falco/types"
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

func (f *FastlyApiFetcher) Backends() ([]*types.RemoteBackend, error) {
	ctx, timeout := _context.WithTimeout(_context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	fstlyBack, err := f.client.ListBackends(ctx, version)
	if err != nil {
		return nil, err
	}
	r := []*types.RemoteBackend{}
	for _, b := range fstlyBack {
		r = append(r, &types.RemoteBackend{
			Name:    b.Name,
			Shield:  b.Shield,
			Address: b.Address,
		})
	}
	return r, nil
}
func (f *FastlyApiFetcher) Dictionaries() ([]*types.RemoteDictionary, error) {
	c, timeout := _context.WithTimeout(_context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	fstlyDic, err := f.client.ListEdgeDictionaries(c, version)
	if err != nil {
		return nil, err
	}

	r := []*types.RemoteDictionary{}
	for _, d := range fstlyDic {
		r = append(r, &types.RemoteDictionary{
			Name: d.Name,
		})
	}
	return r, nil
}
func (f *FastlyApiFetcher) Acls() ([]*types.RemoteAcl, error) {
	c, timeout := _context.WithTimeout(_context.Background(), f.timeout)
	defer timeout()
	version, err := f.getVersion(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	fastlyAcls, err := f.client.ListAccessControlLists(c, version)
	if err != nil {
		return nil, err
	}

	r := []*types.RemoteAcl{}
	for _, a := range fastlyAcls {
		r = append(r, &types.RemoteAcl{
			Name: a.Name,
		})
	}
	return r, nil
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

func (f *FastlyApiFetcher) Snippets() ([]*types.RemoteVCL, error) {
	c, timeout := context.WithTimeout(_context.Background(), f.timeout)
	defer timeout()

	version, err := f.getVersion(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	fastlyVcls, err := f.client.ListSnippets(c, version)
	if err != nil {
		return nil, err
	}

	var r []*types.RemoteVCL
	for _, v := range fastlyVcls {
		p, err := strconv.ParseInt(v.Priority, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("Failed to convert VCL snippet priority to int: %w", err)
		}

		r = append(r, &types.RemoteVCL{
			Name:     v.Name,
			Type:     v.Type,
			Content:  *v.Content,
			Priority: p,
		})
	}
	return r, nil
}

func (f *FastlyApiFetcher) LoggingEndpoints() ([]string, error) {
	c, timeout := context.WithTimeout(_context.Background(), f.timeout)
	defer timeout()

	version, err := f.getVersion(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to get latest version %w", err)
	}

	return f.client.ListLoggingEndpoints(c, version)
}
