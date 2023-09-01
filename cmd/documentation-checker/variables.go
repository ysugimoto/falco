package main

import (
	"context"
	"os"
	"sync"

	"github.com/go-yaml/yaml"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

var fastlyVariableCategoryPageUrls = []string{
	"/reference/vcl/variables/backend-connection/",
	"/reference/vcl/variables/backend-request/",
	"/reference/vcl/variables/backend-response/",
	"/reference/vcl/variables/cache-object/",
	"/reference/vcl/variables/client-connection/",
	"/reference/vcl/variables/client-request/",
	"/reference/vcl/variables/client-response/",
	"/reference/vcl/variables/date-and-time/",
	"/reference/vcl/variables/esi/",
	"/reference/vcl/variables/geolocation/",
	"/reference/vcl/variables/math-constants-limits/",
	"/reference/vcl/variables/miscellaneous/",
	"/reference/vcl/variables/rate-limiting/",
	"/reference/vcl/variables/segmented-caching/",
	"/reference/vcl/variables/server/",
	"/reference/vcl/variables/waf/",
}

const predefinedPath = "../../__generator__/predefined.yml"

func factoryVariables(ctx context.Context) (*sync.Map, error) {
	var eg errgroup.Group
	var m sync.Map
	for i := range fastlyVariableCategoryPageUrls {
		url := fastlyDocDomain + fastlyVariableCategoryPageUrls[i]
		eg.Go(func() error {
			return fetchFastlyDocument(ctx, url, &m)
		})
	}
	if err := eg.Wait(); err != nil {
		return &m, errors.WithStack(err)
	}
	return &m, nil
}

func checkVariables(m *sync.Map) error {
	fp, err := os.Open(predefinedPath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer fp.Close()

	variables := make(map[string]interface{})
	if err := yaml.NewDecoder(fp).Decode(variables); err != nil {
		return errors.WithStack(err)
	}

	m.Range(func(key, val interface{}) bool {
		k := key.(string) //nolint:errcheck
		v := val.(string) //nolint:errcheck

		if _, ok := variables[k]; ok {
			return true
		}
		write(yellow, "[!] ")
		writeln(white, `"%s" is not defined, url: %s`, k, v)
		return true
	})
	return nil
}
