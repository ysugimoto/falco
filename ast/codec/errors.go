package codec

import "fmt"

type DecodeError struct {
	original error
}

func (d *DecodeError) Error() string {
	return fmt.Sprintf("Decode error: %s", d.original.Error())
}

func (d *DecodeError) Unwrap() error {
	return d.original
}

func decodeError(err error) *DecodeError {
	return &DecodeError{
		original: err,
	}
}

func typeMismatch(expect, actual FrameType) *DecodeError {
	return &DecodeError{
		original: fmt.Errorf("Expect type %s but got %s", expect.String(), actual.String()),
	}
}

func unexpectedFinByte() *DecodeError {
	return &DecodeError{
		original: fmt.Errorf("Unexpected FIN byte found"),
	}
}
