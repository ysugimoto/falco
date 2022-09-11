package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pkg/errors"
)

// StdinResolver is in memory resolver, read and factory vcl data from terraform planned JSON input
type StdinResolver struct {
	Modules     []*VCL
	Main        *VCL
	b           []Backend
	d           []Dictionary
	a           []Acl
	ServiceName string
}

func (s *StdinResolver) Backends() ([]Backend, error) {
	return s.b, nil
}

func (s *StdinResolver) Dictionaries() ([]Dictionary, error) {
	return s.d, nil
}

func (s *StdinResolver) Acls() ([]Acl, error) {
	return s.a, nil
}

func NewStdinResolvers() ([]Resolver, error) {
	// Consider reading from stdin timeout to not to hang up in CI flow
	input := make(chan []byte)
	errChan := make(chan error)

	go func() {
		buf, err := io.ReadAll(os.Stdin)
		if err != nil {
			errChan <- err
			return
		}
		input <- buf
	}()

	var resolvers []Resolver
	select {
	case buf := <-input:
		services, err := unmarshalTerraformPlannedInput(buf)
		if err != nil {
			return nil, err
		}
		for _, v := range services {
			s := &StdinResolver{
				ServiceName: v.Name,
			}
			for _, vcl := range v.Vcls {
				if vcl.Main {
					s.Main = &VCL{
						Name: vcl.Name,
						Data: vcl.Content,
					}
				} else {
					s.Modules = append(s.Modules, &VCL{
						Name: vcl.Name,
						Data: vcl.Content,
					})
				}
			}

			for _, backend := range v.Backends {
				s.b = append(s.b, Backend{
					Name: fmt.Sprintf("F_%s", backend.Name),
				})
			}

			for _, acl := range v.Acls {
				s.a = append(s.a, Acl{
					Name: acl.Name,
				})
			}

			for _, dictionary := range v.Dictionaries {
				s.d = append(s.d, Dictionary{
					Name: dictionary.Name,
				})
			}

			resolvers = append(resolvers, s)
		}
		return resolvers, nil
	case err := <-errChan:
		return nil, errors.New(fmt.Sprintf("Failed to read from stdin: %s", err.Error()))
	case <-time.After(10 * time.Second):
		return nil, errors.New(("Failed to read from stdin: timed out"))
	}
}

func (s *StdinResolver) Name() string {
	return s.ServiceName
}

func (s *StdinResolver) MainVCL() (*VCL, error) {
	return s.Main, nil
}

func (s *StdinResolver) Resolve(module string) (*VCL, error) {
	for i := range s.Modules {
		if s.Modules[i].Name == module {
			return s.Modules[i], nil
		}
	}

	return nil, errors.New(fmt.Sprintf("Failed to resolve include file: %s.vcl", module))
}
