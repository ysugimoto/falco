package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const (
	fastlyDocColumnWrapperClassPrefix = "columns-list-module--columnList2"
	ignoreHTTPHeaderRelatedSignaure   = "{NAME}"
	ignoreRegexCapturedNumber         = "{N}"
	ignoreFunctionIf                  = "if"
)

func fetchFastlyDocument(ctx context.Context, url string, m *sync.Map) error {
	c, timeout := context.WithTimeout(ctx, 5*time.Second)
	defer timeout()

	req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
	if err != nil {
		return errors.WithStack(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.WithStack(err)
	} else if resp.StatusCode != http.StatusOK {
		return errors.WithStack(fmt.Errorf("Uexpected status code: %d, url: %s", resp.StatusCode, url))
	}
	node, err := html.Parse(resp.Body)
	if err != nil {
		return errors.WithStack(err)
	}
	wrapper := findLinkWrapperNode(node)
	if wrapper == nil {
		return errors.WithStack(fmt.Errorf("Wrapper node is nil, url: %s", url))
	}
	for c := wrapper.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode || c.DataAtom != atom.Li {
			continue
		}
		for a := c.FirstChild; a != nil; a = a.NextSibling {
			if a.Type != html.ElementNode || a.DataAtom != atom.A {
				continue
			}
			name := a.FirstChild.Data
			if name == ignoreFunctionIf ||
				strings.Contains(name, ignoreRegexCapturedNumber) {

				continue
			}

			name = strings.ReplaceAll(
				name,
				ignoreHTTPHeaderRelatedSignaure,
				"%any%",
			)

			var link string
			for _, v := range a.Attr {
				if v.Key == "href" {
					link = v.Val
					break
				}
			}
			m.Store(name, fastlyDocDomain+link)
		}
	}

	return nil
}

func findLinkWrapperNode(node *html.Node) *html.Node {
	for c := node.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		if c.DataAtom == atom.Ul {
			var class string
			for _, v := range c.Attr {
				if v.Key == "class" {
					class = v.Val
					break
				}
			}
			if strings.Contains(class, fastlyDocColumnWrapperClassPrefix) {
				return c
			}
		}
		if v := findLinkWrapperNode(c); v != nil {
			return v
		}
	}
	return nil
}
