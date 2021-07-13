package remote

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
)

const (
	fastlyApiBaseUrl = "https://api.fastly.com"
)

type FastlyClient struct {
	serviceId string
	apiKey    string
	client    *http.Client
}

func NewFastlyClient(c *http.Client, serviceId, apiKey string) *FastlyClient {
	return &FastlyClient{
		serviceId: serviceId,
		apiKey:    apiKey,
		client:    c,
	}
}

func (c *FastlyClient) request(ctx context.Context, method, url string, body io.Reader, v interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, fastlyApiBaseUrl+url, body)
	if err != nil {
		return errors.WithStack(err)
	}
	req.Header.Set("Fastly-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return errors.WithStack(err)
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API respond not 200 code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (c *FastlyClient) LatestVersion(ctx context.Context) (int64, error) {
	ctx, timeout := context.WithTimeout(ctx, 5*time.Second)
	defer timeout()

	endpoint := fmt.Sprintf("/service/%s/version/active", c.serviceId)
	var v Version
	if err := c.request(ctx, http.MethodGet, endpoint, nil, &v); err != nil {
		return 0, errors.WithStack(err)
	}

	return v.Number, nil
}

func (c *FastlyClient) ListEdgeDictionaries(ctx context.Context, version int64) ([]*EdgeDictionary, error) {
	endpoint := fmt.Sprintf("/service/%s/version/%d/dictionary", c.serviceId, version)
	var dicts []*EdgeDictionary
	if err := c.request(ctx, http.MethodGet, endpoint, nil, &dicts); err != nil {
		return nil, errors.WithStack(err)
	}

	var wg sync.WaitGroup
	var once sync.Once
	errch := make(chan error)
	for _, d := range dicts {
		wg.Add(1)
		go func(d *EdgeDictionary) {
			defer wg.Done()
			var err error
			if d.Items, err = c.ListEdgeDictionaryItems(ctx, d.Id); err != nil {
				once.Do(func() {
					errch <- err
				})
			}
		}(d)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return dicts, nil
	case err := <-errch:
		return nil, err
	}
}

func (c *FastlyClient) ListEdgeDictionaryItems(ctx context.Context, dictId string) ([]*EdgeDictionaryItem, error) {
	endpoint := fmt.Sprintf("/service/%s/dictionary/%s/items", c.serviceId, dictId)
	var items []*EdgeDictionaryItem
	if err := c.request(ctx, http.MethodGet, endpoint, nil, &items); err != nil {
		return nil, errors.WithStack(err)
	}

	return items, nil
}
