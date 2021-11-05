package main

import (
	"fmt"
	"io"

	"os/exec"
)

type Transformer struct {
	command string
	bin     string
}

func NewTransformer(name string) (*Transformer, error) {
	command := fmt.Sprintf("falco-transform-%s", name)
	bin, err := exec.LookPath(command)
	if err != nil {
		return nil, fmt.Errorf(`Transformer command "%s" does not exist in PATH`, command)
	}
	return &Transformer{
		command: command,
		bin:     bin,
	}, nil
}

func (t *Transformer) Execute(d io.Reader) error {
	cmd := exec.Command(t.bin)
	cmd.Stdin = d
	cmd.Stdout = t
	cmd.Stderr = t

	return cmd.Run()
}

func (t *Transformer) Write(v []byte) (int, error) {
	write(magenta, "["+t.command+"] ")
	write(white, string(v))

	return len(v), nil
}
