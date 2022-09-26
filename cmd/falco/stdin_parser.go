package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/terraform"
)

func ParseStdin() ([]*terraform.FastlyService, error) {
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

	select {
	case buf := <-input:
		return terraform.UnmarshalTerraformPlannedInput(buf)
	case err := <-errChan:
		return nil, errors.New(fmt.Sprintf("Failed to read from stdin: %s", err.Error()))
	case <-time.After(10 * time.Second):
		return nil, errors.New(("Failed to read from stdin: timed out"))
	}
}
