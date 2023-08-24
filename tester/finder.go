package tester

import (
	"io/fs"
	"path/filepath"
	"strings"
)

type finder struct {
	root        string
	files       []string
	lookupCache map[string]struct{}
}

func Finder(root string) *finder {
	abs, _ := filepath.Abs(root) // notlint:errcheck
	return &finder{
		root: abs,
		lookupCache: map[string]struct{}{
			abs: {},
		},
	}
}
func (f *finder) Find() ([]string, error) {
	err := filepath.WalkDir(f.root, f.find)
	if err != nil {
		return nil, err
	}
	return f.files, nil
}

// fs.WalkDirFunc inplementation
func (f *finder) find(path string, entry fs.DirEntry, err error) error {
	if err != nil {
		if _, ok := err.(*fs.PathError); ok {
			return nil
		}
		return err
	}
	if !strings.HasSuffix(path, ".test.vcl") {
		return nil
	}
	f.files = append(f.files, path)
	return nil
}
