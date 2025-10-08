package snippets

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/ysugimoto/falco/remote"
	"github.com/ysugimoto/falco/types"
	"golang.org/x/sync/errgroup"
)

type Fetcher interface {
	Backends() ([]*types.RemoteBackend, error)
	Directors() ([]*types.RemoteDirector, error)
	Dictionaries() ([]*types.RemoteDictionary, error)
	Acls() ([]*types.RemoteAcl, error)
	Snippets() ([]*types.RemoteVCL, error)
	LoggingEndpoints() ([]string, error)
}

func Fetch(fetcher Fetcher) (*Snippets, error) {
	snippets := &Snippets{
		ScopedSnippets:   make(map[string][]SnippetItem),
		IncludeSnippets:  make(map[string]SnippetItem),
		LoggingEndpoints: make(map[string]struct{}),
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

	if err := eg.Wait(); err != nil {
		fmt.Println("Error!")
		return nil, err
	}
	fmt.Println("Done.")
	return snippets, nil
}

func fetchEdgeDictionary(fetcher Fetcher) ([]SnippetItem, error) {
	dicts, err := fetcher.Dictionaries()
	if err != nil {
		return nil, fmt.Errorf("Failed to get edge dictionaries %w", err)
	}

	tmpl, err := template.New("table").Parse(tableTemplate)
	if err != nil {
		return nil, fmt.Errorf("Failed to compile table template: %w", err)
	}

	var snippets []SnippetItem
	for _, dict := range dicts {
		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, dict); err != nil {
			return nil, fmt.Errorf("Failed to render table template: %w", err)
		}
		snippets = append(snippets, SnippetItem{
			Name: fmt.Sprintf("Remote.EdgeDictionary:%s", dict.Name),
			Data: buf.String(),
		})
	}
	return snippets, nil
}

func fetchAccessControl(fetcher Fetcher) ([]SnippetItem, error) {
	acls, err := fetcher.Acls()
	if err != nil {
		return nil, fmt.Errorf("Failed to get ACLs: %w", err)
	}

	tmpl, err := template.New("acl").Parse(aclTemplate)
	if err != nil {
		return nil, fmt.Errorf("Failed to compile acl template: %w", err)
	}

	var snippets []SnippetItem
	for _, a := range acls {
		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, a); err != nil {
			return nil, fmt.Errorf("Failed to render acl template: %w", err)
		}
		snippets = append(snippets, SnippetItem{
			Name: fmt.Sprintf("Remote.Acl:%s", a.Name),
			Data: buf.String(),
		})
	}
	return snippets, nil
}

func fetchBackend(fetcher Fetcher) ([]SnippetItem, error) {
	var snippets []SnippetItem
	backends, err := fetcher.Backends()
	if err != nil {
		return nil, fmt.Errorf("Failed to get Backends: %w", err)
	}
	if len(backends) == 0 {
		return snippets, nil
	}
	backTmpl, err := template.New("backend").Parse(backendTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to compile backend template: %w", err)
	}

	for _, b := range backends {
		buf := new(bytes.Buffer)
		b.Name = TerraformBackendNameSanitizer(b.Name)
		if err := backTmpl.Execute(buf, b); err != nil {
			return nil, fmt.Errorf("failed to render backend template: %w", err)
		}
		snippets = append(snippets, SnippetItem{
			Name: fmt.Sprintf("Remote.Backend:%s", b.Name),
			Data: buf.String(),
		})
	}

	// Generate director snippet only when at least one backend is declared
	if len(backends) > 0 {
		directors, err := renderBackendShields(backends)
		if err != nil {
			return nil, err
		}
		snippets = append(snippets, directors...)
	}

	return snippets, nil
}

func fetchDirector(fetcher Fetcher) ([]SnippetItem, error) {
	var snippets []SnippetItem
	directors, err := fetcher.Directors()
	if err != nil {
		return nil, fmt.Errorf("Failed to get Directors: %w", err)
	}
	if len(directors) == 0 {
		return snippets, nil
	}

	printType := func(dtype int) string {
		switch remote.DirectorType(dtype) {
		case remote.Random:
			return "random"
		case remote.Hash:
			return "hash"
		case remote.Client:
			return "client"
		case remote.Shield:
			return "shield"
		}
		return ""
	}
	directorTmpl, err := template.New("director").
		Funcs(template.FuncMap{"printtype": printType}).
		Parse(directorTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to compile director template: %w", err)
	}

	for _, d := range directors {
		// The .retries property enables only for random director
		// https://www.fastly.com/documentation/reference/vcl/declarations/director/
		if remote.DirectorType(d.Type) != remote.Random {
			d.Retries = 0 // zero won't be rendered in the template
		}

		// Director name can be registered including "-" string but invalid in the VCL.
		// Fastly will replace its name from "-" to "_" so we should follow it.
		d.Name = TerraformBackendNameSanitizer(d.Name)

		buf := new(bytes.Buffer)
		if err := directorTmpl.Execute(buf, d); err != nil {
			return nil, fmt.Errorf("failed to render director template: %w", err)
		}
		snippets = append(snippets, SnippetItem{
			Name: fmt.Sprintf("Remote.Director:%s", d.Name),
			Data: buf.String(),
		})
	}

	return snippets, nil
}

func renderBackendShields(backends []*types.RemoteBackend) ([]SnippetItem, error) {
	printType := func(dtype remote.DirectorType) string {
		switch dtype {
		case remote.Random:
			return "random"
		case remote.Hash:
			return "hash"
		case remote.Client:
			return "client"
		case remote.Shield:
			return "shield"
		}
		return ""
	}

	dirTmpl, err := template.New("director").
		Funcs(template.FuncMap{"printtype": printType}).
		Parse(shieldDirectorTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to compile director template: %w", err)
	}

	shieldDirectors := make(map[string]struct{})
	for _, b := range backends {
		if b.Shield != nil && *b.Shield != "" {
			shieldDirectors[*b.Shield] = struct{}{}
		}
	}

	var snippets []SnippetItem
	for sd := range shieldDirectors {
		d := remote.Director{
			Name:     "ssl_shield_" + strings.ReplaceAll(sd, "-", "_"),
			Type:     remote.Shield,
			Backends: []string{},
		}
		buf := new(bytes.Buffer)
		if err := dirTmpl.Execute(buf, d); err != nil {
			return nil, fmt.Errorf("failed to render director template: %w", err)
		}
		snippets = append(snippets, SnippetItem{
			Name: fmt.Sprintf("Remote.Director:%s", d.Name),
			Data: buf.String(),
		})
	}

	return snippets, nil
}

func fetchVCLSnippets(fetcher Fetcher) (
	map[string][]SnippetItem,
	map[string]SnippetItem,
	error,
) {

	snippets, err := fetcher.Snippets()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get VCL snippets: %w", err)
	}

	// Sort by priority
	sort.Slice(snippets, func(i, j int) bool {
		return snippets[i].Priority < snippets[j].Priority
	})

	scoped := make(map[string][]SnippetItem)
	include := make(map[string]SnippetItem)
	for _, snip := range snippets {
		// "none" type means that user could include the snippet arbitrary
		if snip.Type == "none" {
			include[snip.Name] = SnippetItem{
				Name: snip.Name,
				Data: snip.Content,
			}
			continue
		}
		// Otherwise, factory with type (phase) name
		if _, ok := scoped[snip.Type]; !ok {
			scoped[snip.Type] = []SnippetItem{}
		}
		scoped[snip.Type] = append(scoped[snip.Type], SnippetItem{
			Name: snip.Name,
			Data: snip.Content,
		})
	}

	return scoped, include, nil
}
