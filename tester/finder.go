package tester

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

type finder struct {
	files []string
}

// fs.WalkDirFunc implementation
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

func findTestTargetFiles(root string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	f := &finder{}
	if err := filepath.WalkDir(abs, f.find); err != nil {
		return nil, errors.WithStack(err)
	}
	return f.files, nil
}
