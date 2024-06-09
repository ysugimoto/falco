package codec

import (
	"io"
	"sync"
)

var framePool = sync.Pool{
	New: func() any {
		buf := make([]byte, 512)
		return &buf
	},
}

type Frame struct {
	frameType FrameType
	size      int
	buffer    []byte
}

func (f *Frame) Type() FrameType {
	return f.frameType
}

func (f *Frame) String() string {
	return f.frameType.String()
}

func (f *Frame) Read(r io.Reader) ([]byte, error) {
	buf := framePool.Get().(*[]byte) // nolint:errcheck
	defer framePool.Put(buf)

	lr := io.LimitReader(r, int64(f.size))
	var bin []byte
	var read int
	for {
		n, err := lr.Read(*buf)
		if err != nil {
			return nil, err // probably EOF, but raise an error
		}
		read += n
		bin = append(bin, (*buf)[:n]...)
		if read == f.size {
			break
		}
	}

	return bin, nil
}

func (f *Frame) Encode() []byte {
	size := len(f.buffer)

	meta := []byte{
		byte(f.frameType),
		byte(size >> 8),
		byte(size & 0xFF),
	}
	return append(meta, f.buffer...)
}
