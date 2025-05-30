package remote

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
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

func (c *FastlyClient) request(ctx context.Context, url string, v any) error {
	// falco always call API with GET request because we DO NOT change any resources
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fastlyApiBaseUrl+url, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	req.Header.Set("Fastly-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return errors.WithStack(err)
	} else if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return errors.WithStack(err)
		}
		return fmt.Errorf("API respond not 200 code: %d\nBody: %s", resp.StatusCode, buf.String())
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
	if err := c.request(ctx, endpoint, &v); err != nil {
		return 0, errors.WithStack(err)
	}

	return v.Number, nil
}

func (c *FastlyClient) ListConditions(ctx context.Context, version int64) ([]*Condition, error) {
	endpoint := fmt.Sprintf("/service/%s/version/%d/condition", c.serviceId, version)
	var conds []*Condition
	if err := c.request(ctx, endpoint, &conds); err != nil {
		return nil, errors.WithStack(err)
	}

	return conds, nil
}

func (c *FastlyClient) ListEdgeDictionaries(ctx context.Context, version int64) ([]*EdgeDictionary, error) {
	endpoint := fmt.Sprintf("/service/%s/version/%d/dictionary", c.serviceId, version)
	var dicts []*EdgeDictionary
	if err := c.request(ctx, endpoint, &dicts); err != nil {
		return nil, errors.WithStack(err)
	}

	var wg sync.WaitGroup
	var once sync.Once
	errch := make(chan error)
	for _, d := range dicts {
		// If WriteOnly field is true, the dictionary is private.
		// The private dictionary could not access its items so we should prevent to fetch items.
		// Then dictionary items are empty but it's OK for linting
		if d.WriteOnly {
			// Explicit empty items
			d.Items = []*EdgeDictionaryItem{}
			continue
		}

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
	if err := c.request(ctx, endpoint, &items); err != nil {
		return nil, errors.WithStack(err)
	}

	return items, nil
}

func (c *FastlyClient) ListAccessControlLists(ctx context.Context, version int64) ([]*AccessControl, error) {
	endpoint := fmt.Sprintf("/service/%s/version/%d/acl", c.serviceId, version)
	var acls []*AccessControl
	if err := c.request(ctx, endpoint, &acls); err != nil {
		return nil, errors.WithStack(err)
	}

	var wg sync.WaitGroup
	var once sync.Once
	errch := make(chan error)
	for _, a := range acls {
		wg.Add(1)
		go func(a *AccessControl) {
			defer wg.Done()
			var err error
			if a.Entries, err = c.ListAccessControlEntries(ctx, a.Id); err != nil {
				once.Do(func() {
					errch <- err
				})
			}
		}(a)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return acls, nil
	case err := <-errch:
		return nil, err
	}
}

func (c *FastlyClient) ListAccessControlEntries(ctx context.Context, aclId string) ([]*AccessControlEntry, error) {
	endpoint := fmt.Sprintf("/service/%s/acl/%s/entries", c.serviceId, aclId)
	var entries []*AccessControlEntry
	if err := c.request(ctx, endpoint, &entries); err != nil {
		return nil, errors.WithStack(err)
	}

	return entries, nil
}

func (c *FastlyClient) ListBackends(ctx context.Context, version int64) ([]*Backend, error) {
	endpoint := fmt.Sprintf("/service/%s/version/%d/backend", c.serviceId, version)
	var backends []*Backend
	if err := c.request(ctx, endpoint, &backends); err != nil {
		return nil, errors.WithStack(err)
	}

	return backends, nil
}

func (c *FastlyClient) ListDirectors(ctx context.Context, version int64) ([]*Director, error) {
	endpoint := fmt.Sprintf("/service/%s/version/%d/director", c.serviceId, version)
	var directors []*Director
	if err := c.request(ctx, endpoint, &directors); err != nil {
		return nil, errors.WithStack(err)
	}

	return directors, nil
}

func (c *FastlyClient) ListSnippets(ctx context.Context, version int64) ([]*VCLSnippet, error) {
	endpoint := fmt.Sprintf("/service/%s/version/%d/snippet", c.serviceId, version)
	var snippets []*VCLSnippet
	if err := c.request(ctx, endpoint, &snippets); err != nil {
		return nil, errors.WithStack(err)
	}

	// Could not dynamic snippet content from this API response so we need to call more API to get snippet content
	var wg sync.WaitGroup
	var once sync.Once
	errch := make(chan error)
	for _, s := range snippets {
		wg.Add(1)
		go func(s *VCLSnippet) {
			defer wg.Done()
			if s.Dynamic == "0" {
				return
			}
			var err error
			if s.Content, err = c.getDynamicSnippetContent(ctx, s.Id); err != nil {
				once.Do(func() {
					errch <- err
				})
			}
		}(s)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return snippets, nil
	case err := <-errch:
		return nil, err
	}
}

func (c *FastlyClient) getDynamicSnippetContent(ctx context.Context, snippetId string) (*string, error) {
	endpoint := fmt.Sprintf("/service/%s/snippet/%s", c.serviceId, snippetId)
	var snippet struct {
		Content string `json:"content"`
	}
	if err := c.request(ctx, endpoint, &snippet); err != nil {
		return nil, errors.WithStack(err)
	}

	return &snippet.Content, nil
}

var fastlyRealtimeLoggingTypes = []string{
	"bigquery",
	"cloudfiles",
	"datadog",
	"digitalocean",
	"elasticsearch",
	"ftp",
	"gcs",
	"pubsub",
	"https",
	"heroku",
	"honeycomb",
	"kafka",
	"kinesis",
	"logshuttle",
	"loggly",
	"azureblob",
	"newrelic",
	"newrelicotlp",
	"openstack",
	"papertrail",
	"s3",
	"sftp",
	"scalyr",
	"splunk",
	"sumologic",
	"syslog",
}

type listLoggingEndpointResponse struct {
	Name string `json:"name"`
}

func (c *FastlyClient) ListLoggingEndpoints(ctx context.Context, version int64) ([]string, error) {
	var endpoints []string
	var eg errgroup.Group

	basePath := fmt.Sprintf("/service/%s/version/%d/logging", c.serviceId, version)
	for i := range fastlyRealtimeLoggingTypes {
		eg.Go(c.listLoggingEndpoint(ctx, &endpoints, basePath+"/"+fastlyRealtimeLoggingTypes[i]))
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return endpoints, nil
}

func (c *FastlyClient) listLoggingEndpoint(ctx context.Context, endpoints *[]string, path string) func() error {
	return func() error {
		var resp []listLoggingEndpointResponse
		if err := c.request(ctx, path, &resp); err != nil {
			return err
		}
		for i := range resp {
			*endpoints = append(*endpoints, resp[i].Name)
		}
		return nil
	}
}
