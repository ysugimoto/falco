package remote

import (
	"context"
	"errors"
	"strings"
	"testing"

	"io/ioutil"
	"net/http"
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
