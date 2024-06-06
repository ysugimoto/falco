package codec

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"sync"
	"unicode/utf8"

	"github.com/k0kubun/pp"
	"github.com/ysugimoto/falco/ast"
)

var unpackPool = sync.Pool{
	New: func() any {
		return make([]byte, 512)
	},
}

func unpack(r io.Reader) (AstType, io.Reader, error) {
	buf := unpackPool.Get().([]byte)
	defer unpackPool.Put(buf)

	if _, err := io.LimitReader(r, 1).Read(buf); err != nil {
		if err == io.EOF {
			return UNKNOWN, nil, nil
		}
		return UNKNOWN, nil, err
	}

	astType := AstType(buf[0])
	// Terminating byte
	if astType == END {
		return END, nil, nil
	}

	if _, err := io.LimitReader(r, 2).Read(buf); err != nil {
		return UNKNOWN, nil, err
	}
	upper := int(buf[0])
	size := (upper << 8) | int(buf[1])
	if size == 0 {
		return astType, nil, nil
	}

	lr := io.LimitReader(r, int64(size))
	var bin []byte
	var read int
	for {
		n, err := lr.Read(buf)
		if err != nil {
			pp.Println(n)
			return UNKNOWN, nil, err // probably EOF, but raise an error
		}
		read += n
		bin = append(bin, buf[:n]...)
		if read == size {
			break
		}
	}

	return astType, bytes.NewReader(bin), nil
}

func bytesToString(b []byte) string {
	var ret []rune

	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		ret = append(ret, r)
		b = b[size:]
	}

	return string(ret)
}

func unpackIdent(r io.Reader) (*ast.Ident, error) {
	t, r, err := unpack(r)
	if err != nil {
		return nil, decodeError(err)
	}
	if t != IDENT_VALUE {
		return nil, typeMismatch(IDENT_VALUE, t)
	}

	bin, err := io.ReadAll(r)
	if err != nil {
		return nil, decodeError(err)
	}

	return &ast.Ident{
		Value: bytesToString(bin),
	}, nil
}

func unpackString(r io.Reader) (*ast.String, error) {
	t, r, err := unpack(r)
	if err != nil {
		return nil, decodeError(err)
	}
	if t != STRING_VALUE {
		return nil, typeMismatch(STRING_VALUE, t)
	}

	bin, err := io.ReadAll(r)
	if err != nil {
		return nil, decodeError(err)
	}

	return &ast.String{
		Value: bytesToString(bin),
	}, nil
}

func unpackIP(r io.Reader) (*ast.IP, error) {
	t, r, err := unpack(r)
	if err != nil {
		return nil, decodeError(err)
	}
	if t != IP_VALUE {
		return nil, typeMismatch(IP_VALUE, t)
	}

	bin, err := io.ReadAll(r)
	if err != nil {
		return nil, decodeError(err)
	}

	return &ast.IP{
		Value: bytesToString(bin),
	}, nil
}

func unpackInteger(r io.Reader) (*ast.Integer, error) {
	t, r, err := unpack(r)
	if err != nil {
		return nil, decodeError(err)
	}
	if t != INTEGER_VALUE {
		return nil, typeMismatch(INTEGER_VALUE, t)
	}

	bin, err := io.ReadAll(r)
	if err != nil {
		return nil, decodeError(err)
	}

	v := binary.BigEndian.Uint64(bin)
	return &ast.Integer{
		Value: int64(v),
	}, nil
}

func unpackFloat(r io.Reader) (*ast.Float, error) {
	t, r, err := unpack(r)
	if err != nil {
		return nil, decodeError(err)
	}
	if t != FLOAT_VALUE {
		return nil, typeMismatch(FLOAT_VALUE, t)
	}

	bin, err := io.ReadAll(r)
	if err != nil {
		return nil, decodeError(err)
	}

	bits := binary.BigEndian.Uint64(bin)
	return &ast.Float{
		Value: math.Float64frombits(bits),
	}, nil
}

func unpackBoolean(r io.Reader) (*ast.Boolean, error) {
	t, r, err := unpack(r)
	if err != nil {
		return nil, decodeError(err)
	}
	if t != BOOL_VALUE {
		return nil, typeMismatch(BOOL_VALUE, t)
	}

	bin, err := io.ReadAll(r)
	if err != nil {
		return nil, decodeError(err)
	}

	return &ast.Boolean{
		Value: bin[0] == 0x01,
	}, nil
}
