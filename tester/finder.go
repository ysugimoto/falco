package tester

import (
	"io/fs"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ryanuber/go-glob"
)

type finder struct {
	files  []string
	filter string
}

// fs.WalkDirFunc implementation
func (f *finder) find(path string, entry fs.DirEntry, err error) error {
	if err != nil {
		if _, ok := err.(*fs.PathError); ok {
			return nil
		}
		return err
	}
	if !glob.Glob(f.filter, path) {
		return nil
	}
	f.files = append(f.files, path)
	return nil
}

func findTestTargetFiles(root, filter string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	f := &finder{
		filter: filter,
	}
	if err := filepath.WalkDir(abs, f.find); err != nil {
		return nil, errors.WithStack(err)
	}
	return f.files, nil
}
