package remote

import (
	"context"
	"strings"
	"testing"

	"io/ioutil"
	"net/http"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
)

type TestRoundTripper struct {
	StatusCode int
	Body       string
}

func (t *TestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("Fastly-Key") == "" {
		return nil, errors.New("Fastly-Key header is required")
	}

	return &http.Response{
		StatusCode: t.StatusCode,
		Body:       ioutil.NopCloser(strings.NewReader(t.Body)),
	}, nil
}

func TestLatestVersion(t *testing.T) {
	c := NewFastlyClient(&http.Client{
		Transport: &TestRoundTripper{
			StatusCode: 200,
			Body: `
{
	"created_at": "2020-04-09T18:14:30.000Z",
	"updated_at": "2020-04-09T18:15:30.000Z",
	"deleted_at": null,
	"active": true,
	"comment": "",
	"deployed": true,
	"locked": false,
	"number": 1,
	"staging": false,
	"testing": false,
	"service_id": "SU1Z0isxPaozGVKXdv0eY"
}`,
		},
	}, "dummy", "dummy")

	version, err := c.LatestVersion(context.Background())
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		t.FailNow()
	}
	if version != 1 {
		t.Errorf("Version assertion error, expects=1 but got=%d", version)
		t.FailNow()
	}
}

func TestListDictionaries(t *testing.T) {
	c := NewFastlyClient(&http.Client{
		Transport: &TestRoundTripper{
			StatusCode: 200,
			Body: `
[
  {
	"created_at": "2020-04-29T22:16:23.000Z",
	"deleted_at": null,
	"id": "3vjTN8v1O7nOAY7aNDGOL",
	"name": "my_dictionary",
	"service_id": "SU1Z0isxPaozGVKXdv0eY",
	"updated_at": "2020-04-29T22:16:23.000Z",
	"version": 1,
	"write_only": false
  }
]`,
		},
	}, "dummy", "dummy")

	dicts, err := c.ListEdgeDictionaries(context.Background(), 10)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		t.FailNow()
	}
	if len(dicts) != 1 {
		t.Errorf("dictionaries should have 1 but got %d", len(dicts))
		t.FailNow()
	}
	d := dicts[0]
	if d.Id != "3vjTN8v1O7nOAY7aNDGOL" {
		t.Errorf("dict id assertion error, expects=3vjTN8v1O7nOAY7aNDGOL but got=%s", d.Id)
		t.FailNow()
	}
	if d.Name != "my_dictionary" {
		t.Errorf("dict name assertion error, expects=my_dictionary but got=%s", d.Name)
		t.FailNow()
	}
}

func TestListDictionaryItems(t *testing.T) {
	c := NewFastlyClient(&http.Client{
		Transport: &TestRoundTripper{
			StatusCode: 200,
			Body: `
[
  {
	"dictionary_id": "3vjTN8v1O7nOAY7aNDGOL",
	"service_id": "SU1Z0isxPaozGVKXdv0eY",
	"item_key": "some_key",
	"item_value": "some_value",
	"created_at": "2020-04-21T18:14:32.000Z",
	"deleted_at": null,
	"updated_at": "2020-04-21T18:14:32.000Z"
  }
]`,
		},
	}, "dummy", "dummy")

	items, err := c.ListEdgeDictionaryItems(context.Background(), "3vjTN8v1O7nOAY7aNDGOL")
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		t.FailNow()
	}
	if len(items) != 1 {
		t.Errorf("dictionaries should have 1 items but got %d", len(items))
		t.FailNow()
	}
	i := items[0]
	if i.Key != "some_key" {
		t.Errorf("item key assertion error, expects=some_key but got=%s", i.Key)
		t.FailNow()
	}
	if i.Value != "some_value" {
		t.Errorf("item value assertion error, expects=some_value but got=%s", i.Value)
		t.FailNow()
	}
}

func TestListAccessControlLists(t *testing.T) {
	c := NewFastlyClient(&http.Client{
		Transport: &TestRoundTripper{
			StatusCode: 200,
			Body: `
[
  {
    "name": "blocked_ips",
    "service_id": "0yGwmmav8rcXRC7yRwzPNQ",
    "id": "1GJz4D4wxiP8DeVCVdYDfo",
    "deleted_at": null,
    "created_at": "2021-11-25T23:40:04Z",
    "updated_at": "2021-11-25T23:40:04Z",
    "version": "10"
  }
]]`,
		},
	}, "dummy", "dummy")

	acls, err := c.ListAccessControlLists(context.Background(), 10)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		t.FailNow()
	}
	if len(acls) != 1 {
		t.Errorf("dictionaries should have 1 but got %d", len(acls))
		t.FailNow()
	}
	a := acls[0]
	if a.Id != "1GJz4D4wxiP8DeVCVdYDfo" {
		t.Errorf("acl id assertion error, expects=1GJz4D4wxiP8DeVCVdYDfo but got=%s", a.Id)
		t.FailNow()
	}
	if a.Name != "blocked_ips" {
		t.Errorf("acl name assertion error, expects=blocked_ips but got=%s", a.Name)
		t.FailNow()
	}
}

func TestListAccessControlEntiries(t *testing.T) {
	c := NewFastlyClient(&http.Client{
		Transport: &TestRoundTripper{
			StatusCode: 200,
			Body: `
[
  {
    "updated_at": "2021-11-25T23:40:33Z",
    "ip": "10.0.0.0",
    "negated": "0",
    "acl_id": "1GJz4D4wxiP8DeVCVdYDfo",
    "id": "4BCmH8eb7p9absKKcaADIp",
    "subnet": 32,
    "service_id": "0yGwmmav8rcXRC7yRwzPNQ",
    "comment": "example",
    "created_at": "2021-11-25T23:40:33Z"
  }
]`,
		},
	}, "dummy", "dummy")

	items, err := c.ListAccessControlEntries(context.Background(), "1GJz4D4wxiP8DeVCVdYDfo")
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		t.FailNow()
	}
	if len(items) != 1 {
		t.Errorf("entries should have 1 items but got %d", len(items))
		t.FailNow()
	}
	i := items[0]
	if i.Ip != "10.0.0.0" {
		t.Errorf("ip assertion error, expects=10.0.0.0 but got=%s", i.Ip)
		t.FailNow()
	}
	if i.Negated != "0" {
		t.Errorf("negated field assertion error, expects=0 but got=%s", i.Negated)
		t.FailNow()
	}
	if *i.Subnet != 32 {
		t.Errorf("subnet field assertion error, expects=32 but got=%d", *i.Subnet)
		t.FailNow()
	}
}

func TestListBackends(t *testing.T) {
	c := NewFastlyClient(&http.Client{
		Transport: &TestRoundTripper{
			StatusCode: 200,
			Body: `
[
  {
    "updated_at": "2021-11-25T23:40:33Z",
		"name": "some_backend",
		"shield": "some_shield",
    "service_id": "0yGwmmav8rcXRC7yRwzPNQ",
    "comment": "example",
    "created_at": "2021-11-25T23:40:33Z"
  }
]`,
		},
	}, "dummy", "dummy")

	items, err := c.ListBackends(context.Background(), 10)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		t.FailNow()
	}
	if len(items) != 1 {
		t.Errorf("backends should have 1 items but got %d", len(items))
		t.FailNow()
	}
	i := items[0]
	if i.Name != "some_backend" {
		t.Errorf("item name assertion error, expects=some_backend but got=%s", i.Name)
		t.FailNow()
	}
	if *i.Shield != "some_shield" {
		t.Errorf("item shield assertion error, expects=some_shield but got=%s", *i.Shield)
		t.FailNow()
	}
}

func TestListConditions(t *testing.T) {
	c := NewFastlyClient(&http.Client{
		Transport: &TestRoundTripper{
			StatusCode: 200,
			Body: `
[
	{
		"version": "10",
		"statement": "req.url.path == \"/robots.txt\"",
		"service_id": "test",
		"type": "REQUEST",
		"name": "Robots",
		"deleted_at": null,
		"created_at": "2022-03-04T06:45:19Z",
		"updated_at": "2025-05-26T06:38:31Z",
		"comment": "",
		"priority": "10"
	}
]`,
		},
	}, "dummy", "dummy")

	conditions, err := c.ListConditions(context.Background(), 10)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		t.FailNow()
	}
	if len(conditions) != 1 {
		t.Errorf("conditions should have 1 items but got %d", len(conditions))
		t.FailNow()
	}

	expect := &Condition{
		Type:      "REQUEST",
		Statement: `req.url.path == "/robots.txt"`,
		Priority:  "10",
		Name:      "Robots",
	}
	if diff := cmp.Diff(expect, conditions[0]); diff != "" {
		t.Errorf("API response result mismatch, diff=%s", diff)
	}
}

func TestListHeaders(t *testing.T) {
	c := NewFastlyClient(&http.Client{
		Transport: &TestRoundTripper{
			StatusCode: 200,
			Body: `
[
  {
    "regex": "/foo(.+)/",
    "service_id": "qRK2E1vLIVkQ3BU0iVk9X7",
    "type": "request",
    "ignore_if_set": "1",
    "request_condition": "request_condition",
    "action": "regex_repeat",
    "dst": "http.Set-Header-Item",
    "updated_at": "2025-05-30T15:41:47Z",
    "cache_condition": null,
    "priority": "10",
    "response_condition": null,
    "src": "req.url",
    "substitution": "$1",
    "version": "23",
    "name": "set_header_request",
    "created_at": "2025-05-30T14:23:57Z",
    "deleted_at": null
  }
]`,
		},
	}, "dummy", "dummy")

	headers, err := c.ListHeaders(context.Background(), 10)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
		t.FailNow()
	}
	if len(headers) != 1 {
		t.Errorf("headers should have 1 items but got %d", len(headers))
		t.FailNow()
	}

	rc := "request_condition"
	expect := &Header{
		Regex:             "/foo(.+)/",
		Type:              "request",
		IgnoreIfSet:       "1",
		RequestCondition:  &rc,
		CacheCondition:    nil,
		ResponseCondition: nil,
		Source:            "req.url",
		Destination:       "http.Set-Header-Item",
		Priority:          "10",
		Action:            "regex_repeat",
		Substitution:      "$1",
		Name:              "set_header_request",
	}
	if diff := cmp.Diff(expect, headers[0]); diff != "" {
		t.Errorf("API response result mismatch, diff=%s", diff)
	}
}
