package codec

import "fmt"

type DecodeError struct {
	original error
}

func (d *DecodeError) Error() string {
	return fmt.Sprintf("%s: %s", d.original.Error())
}

func (d *DecodeError) Unwrap() error {
	return d.original
}

func decodeError(err error) *DecodeError {
	return &DecodeError{
		original: err,
	}
}

func typeMismatch(expect, actual AstType) *DecodeError {
	return &DecodeError{
		original: fmt.Errorf("Expect type %s but got %s", expect, actual),
	}
}
