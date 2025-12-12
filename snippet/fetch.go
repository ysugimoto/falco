package snippet

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

// Fetcher interface represents fetch several resources from some sources.
// Remote Fetcher    - Fastly Managed
// Terraform Fetcher - Terraform Planned Result
type Fetcher interface {
	// Caching methods
	LookupCache(bool) *Snippets
	WriteCache(*Snippets)

	// Resource fetching methods
	Backends() ([]*Backend, error)
	Directors() ([]*Director, error)
	Dictionaries() ([]*Dictionary, error)
	Acls() ([]*Acl, error)
	Conditions() ([]*Condition, error)
	Snippets() ([]*VCLSnippet, error)
	Headers() ([]*Header, error)
	ResponseObjects() ([]*ResponseObject, error)
	RequestSetting() (*RequestSetting, error)
	LoggingEndpoints() ([]string, error)
}

func Fetch(fetcher Fetcher) (*Snippets, error) {
	snippets := &Snippets{
		ScopedSnippets:   ScopedSnippets{},
		IncludeSnippets:  IncludeSnippets{},
		LoggingEndpoints: LoggingEndpoints{},
	}

	var eg errgroup.Group

	fmt.Print("Fething snippets...")
	eg.Go(func() (err error) {
		snippets.Dictionaries, err = fetchEdgeDictionary(fetcher)
		return err
	})
	eg.Go(func() (err error) {
		snippets.Acls, err = fetchAccessControl(fetcher)
		return err
	})
	eg.Go(func() (err error) {
		snippets.Backends, err = fetchBackend(fetcher)
		return err
	})
	eg.Go(func() (err error) {
		snippets.Directors, err = fetchDirector(fetcher)
		return err
	})
	eg.Go(func() (err error) {
		snippets.ScopedSnippets, snippets.IncludeSnippets, err = fetchVCLSnippets(fetcher)
		return err
	})
	eg.Go(func() (err error) {
		snippets.Conditions, err = fetchConditions(fetcher)
		return err
	})
	eg.Go(func() (err error) {
		snippets.Headers, err = fetcher.Headers()
		return err
	})
	eg.Go(func() (err error) {
		snippets.ResponseObjects, err = fetcher.ResponseObjects()
		return err
	})
	eg.Go(func() (err error) {
		snippets.RequestSetting, err = fetcher.RequestSetting()
		return err
	})

	if err := eg.Wait(); err != nil {
		fmt.Println("Error!")
		return nil, errors.WithStack(err)
	}
	fmt.Println("Done.")
	return snippets, nil
}

func fetchEdgeDictionary(fetcher Fetcher) ([]Item, error) {
	dicts, err := fetcher.Dictionaries()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var snippets []Item
	for _, dict := range dicts {
		snip, err := renderDictionary(dict)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		snippets = append(snippets, *snip)
	}
	return snippets, nil
}

func fetchAccessControl(fetcher Fetcher) ([]Item, error) {
	acls, err := fetcher.Acls()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var snippets []Item
	for _, a := range acls {
		snip, err := renderAcl(a)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		snippets = append(snippets, *snip)
	}
	return snippets, nil
}

func fetchBackend(fetcher Fetcher) ([]Item, error) {
	var snippets []Item
	backends, err := fetcher.Backends()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(backends) == 0 {
		return snippets, nil
	}

	for _, b := range backends {
		snip, err := renderBackend(b)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		snippets = append(snippets, *snip)
	}

	// Generate director snippet only when at least one backend is declared
	if len(backends) > 0 {
		directors, err := renderBackendShields(backends)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		snippets = append(snippets, directors...)
	}

	return snippets, nil
}

func fetchDirector(fetcher Fetcher) ([]Item, error) {
	var snippets []Item
	directors, err := fetcher.Directors()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(directors) == 0 {
		return snippets, nil
	}

	for _, d := range directors {
		// The .retries property enables only for random director
		// https://www.fastly.com/documentation/reference/vcl/declarations/director/
		if DirectorType(d.Type) != Random {
			d.Retries = 0 // zero won't be rendered in the template
		}

		snip, err := renderDirector(d, false)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		snippets = append(snippets, *snip)
	}

	return snippets, nil
}

func renderBackendShields(backends []*Backend) ([]Item, error) {
	shieldDirectors := make(map[string]struct{})
	for _, b := range backends {
		if b.Shield != nil && *b.Shield != "" {
			shieldDirectors[*b.Shield] = struct{}{}
		}
	}

	var snippets []Item
	for sd := range shieldDirectors {
		d := &Director{
			Name:     "ssl_shield_" + strings.ReplaceAll(sd, "-", "_"),
			Type:     int(Shield),
			Backends: []string{},
		}
		snip, err := renderDirector(d, true)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		snippets = append(snippets, *snip)
	}

	return snippets, nil
}

func fetchVCLSnippets(fetcher Fetcher) (ScopedSnippets, IncludeSnippets, error) {
	snippets, err := fetcher.Snippets()
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	// Sort by priority
	sort.Slice(snippets, func(i, j int) bool {
		return snippets[i].Priority > snippets[j].Priority
	})

	scoped := ScopedSnippets{}
	include := IncludeSnippets{}
	for _, snip := range snippets {
		// "none" type means that user could include the snippet arbitrary
		if snip.Type == "none" {
			include[snip.Name] = Item{
				Name:     snip.Name,
				Data:     snip.Content,
				Priority: snip.Priority,
			}
			continue
		}
		// Otherwise, factory with type (phase) name
		if _, ok := scoped[snip.Type]; !ok {
			scoped[snip.Type] = []Item{}
		}
		scoped[snip.Type] = append(scoped[snip.Type], Item{
			Name:     snip.Name,
			Data:     snip.Content,
			Priority: snip.Priority,
		})
	}

	return scoped, include, nil
}

func fetchConditions(fetcher Fetcher) (map[string]*Condition, error) {
	conditions, err := fetcher.Conditions()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ret := make(map[string]*Condition)
	for _, cond := range conditions {
		ret[cond.Name] = cond
	}
	return ret, nil
}
