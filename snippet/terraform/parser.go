package terraform

import (
	"fmt"
	"io"
	"time"

	"github.com/pkg/errors"
)

func ParseStdin(in io.Reader) ([]*FastlyService, error) {
	// Consider reading from stdin timeout to not to hang up in CI flow
	input := make(chan []byte)
	errChan := make(chan error)

	go func() {
		buf, err := io.ReadAll(in)
		if err != nil {
			if err == io.EOF {
				return
			}
			errChan <- err
			return
		}
		input <- buf
	}()

	select {
	case buf := <-input:
		return unmarshalTerraformPlannedInput(buf)
	case err := <-errChan:
		return nil, errors.New(fmt.Sprintf("Failed to read from stdin: %s", err.Error()))
	case <-time.After(10 * time.Second):
		return nil, errors.New("Failed to read from stdin: timed out")
	}
}
