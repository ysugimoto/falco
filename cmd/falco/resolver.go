package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"io/ioutil"
	"path/filepath"

	"github.com/pkg/errors"
)

var (
	ErrEmptyMain = errors.New("Input file is empty")
)

type VCL struct {
	Name string
	Data string
}

// Resolver is an interface for integrate VCL input from file or JSON (terraform planned data)
type Resolver interface {
	MainVCL() (*VCL, error)
	Resolve(module string) (*VCL, error)
	Name() string
}

// FileResolver is filesystem resolver, basically used for built vcl files
type FileResolver struct {
	main         string
	includePaths []string
}

func NewFileResolvers(main string, c *Config) ([]Resolver, error) {
	if main == "" {
		return nil, ErrEmptyMain
	}

	if _, err := os.Stat(main); err != nil {
		if err == os.ErrNotExist {
			return nil, errors.New(fmt.Sprintf("Input file %s is not found", main))
		}
		return nil, errors.New(fmt.Sprintf("Unexpected stat error: %s", err.Error()))
	}

	abs, err := filepath.Abs(main)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to get absolute path: %s", err.Error()))
	}

	var includePaths []string
	// Add include paths as absolute
	for i := range c.IncludePaths {
		p, err := filepath.Abs(c.IncludePaths[i])
		if err == nil {
			includePaths = append(includePaths, p)
		}
	}
	includePaths = append(includePaths, filepath.Dir(abs))

	return []Resolver{
		&FileResolver{
			main:         abs,
			includePaths: includePaths,
		},
	}, nil
}

func (f *FileResolver) Name() string {
	return ""
}

func (f *FileResolver) getVCL(file string) (*VCL, error) {
	if _, err := os.Stat(file); err != nil {
		return nil, err
	}
	fp, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(fp); err != nil {
		return nil, err
	}

	return &VCL{
		Name: file,
		Data: buf.String(),
	}, nil
}

func (f *FileResolver) MainVCL() (*VCL, error) {
	return f.getVCL(f.main)
}

func (f *FileResolver) Resolve(module string) (*VCL, error) {
	module_path_with_extension := module
	if !strings.HasSuffix(module_path_with_extension, ".vcl") {
		module_path_with_extension += ".vcl"
	}

	// Find for each include paths
	for _, p := range f.includePaths {
		if vcl, err := f.getVCL(filepath.Join(p, module_path_with_extension)); err == nil {
			return vcl, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("Failed to resolve include file: %s.vcl", module))
}

// StdinResolver is in memory resolver, read and factory vcl data from terraform planned JSON input
type StdinResolver struct {
	Modules     []*VCL
	Main        *VCL
	ServiceName string
}

func NewStdinResolvers() ([]Resolver, error) {
	// Consider reading from stdin timeout to not to hang up in CI flow
	input := make(chan []byte)
	errChan := make(chan error)

	go func() {
		buf, err := ioutil.ReadAll(os.Stdin)
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
