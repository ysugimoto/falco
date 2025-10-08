package resolver

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

// FileResolver is filesystem resolver, basically used for built vcl files
type FileResolver struct {
	main         string
	includePaths []string
}

func NewFileResolvers(main string, includePaths []string) ([]Resolver, error) {
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

	var ips []string
	// Add include paths as absolute
	for i := range includePaths {
		p, err := filepath.Abs(includePaths[i])
		if err == nil {
			ips = append(ips, p)
		}
	}
	ips = append(ips, filepath.Dir(abs))

	return []Resolver{
		&FileResolver{
			main:         abs,
			includePaths: ips,
		},
	}, nil
}

func (f *FileResolver) Name() string {
	return ""
}

func (f *FileResolver) IncludePaths() []string {
	return f.includePaths
}

func getVCL(file string) (*VCL, error) {
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
	return getVCL(f.main)
}

func (f *FileResolver) Resolve(stmt *ast.IncludeStatement) (*VCL, error) {
	modulePathWithExtension := stmt.Module.Value
	if !strings.HasSuffix(modulePathWithExtension, ".vcl") {
		modulePathWithExtension += ".vcl"
	}

	// Find for each include paths
	for _, p := range f.includePaths {
		if vcl, err := getVCL(filepath.Join(p, modulePathWithExtension)); err == nil {
			return vcl, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("Failed to resolve include file: %s", modulePathWithExtension))
}
