package codec

import (
	"io"
	"sync"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
)

var unpackPool = sync.Pool{
	New: func() any {
		return make([]byte, 512)
	},
}

func unpack(r io.Reader) (AstType, []byte, error) {
	buf := unpackPool.Get().([]byte)
	defer unpackPool.Put(buf)

	if _, err := io.LimitReader(r, 1).Read(buf); err != nil {
		if err == io.EOF {
			return UNKNOWN, nil, nil
		}
		return UNKNOWN, nil, err // probably EOF
	}

	astType := AstType(buf[0])
	// Terminating byte
	if astType == END {
		return END, nil, nil
	}

	if _, err := io.LimitReader(r, 2).Read(buf); err != nil {
		return UNKNOWN, nil, err // probably EOF
	}
	upper := int(buf[0])

	size := (upper << 8) | int(buf[1])
	if size == 0 {
		return astType, []byte{}, nil
	}

	var bin []byte
	var read int
	for {
		n, err := r.Read(buf)
		if err != nil {
			return UNKNOWN, nil, err // probably EOF, but raise an error
		}
		read += n
		bin = append(bin, buf...)
		if read == size {
			break
		}
	}

	return astType, buf[:size], nil
}

func unpackIdent(b []byte) (*ast.Ident, error) {
	i, bin, err := unpack(b)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if i != IDENT_VALUE {
	}
}
