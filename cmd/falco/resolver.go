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

// Resolver is an interface for integrate VCL input from file or JSON (terraform planned data)
type Resolver interface {
	MainVCL() (*VCL, error)
	Resolve(module string) (*VCL, error)
	Name() string
}
