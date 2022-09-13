package main

import (
	"github.com/pkg/errors"
)

var (
	ErrEmptyMain = errors.New("Input file is empty")
)

type VCL struct {
	Name string
	Data string
}

type Backend struct {
	Name string
}

type Dictionary struct {
	Name string
}

type Acl struct {
	Name string
}

// Resolver is an interface to fetch VCL source and dependencies
// from various sources e.g. file or JSON (terraform planned data)
type Resolver interface {
	MainVCL() (*VCL, error)
	Resolve(module string) (*VCL, error)
	Name() string
	Backends() ([]Backend, error)
	Dictionaries() ([]Dictionary, error)
	Acls() ([]Acl, error)
}
