package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"path/filepath"

	"github.com/pkg/errors"
)

// FileResolver is filesystem resolver, basically used for built vcl files
type FileResolver struct {
	main         string
	includePaths []string
}

func (f *FileResolver) Backends() ([]Backend, error) {
	return nil, nil
}

func (f *FileResolver) Dictionaries() ([]Dictionary, error) {
	return nil, nil
}

func (f *FileResolver) Acls() ([]Acl, error) {
	return nil, nil
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
	modulePathWithExtension := module
	if !strings.HasSuffix(modulePathWithExtension, ".vcl") {
		modulePathWithExtension += ".vcl"
	}

	// Find for each include paths
	for _, p := range f.includePaths {
		if vcl, err := f.getVCL(filepath.Join(p, modulePathWithExtension)); err == nil {
			return vcl, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("Failed to resolve include file: %s.vcl", module))
}
