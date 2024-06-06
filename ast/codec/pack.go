package codec

import (
	"bytes"
	"encoding/binary"
	"math"
	"sync"
	"unicode/utf8"
)

var packPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func pack(t AstType, bin []byte) []byte {
	buf := packPool.Get().(*bytes.Buffer)
	defer packPool.Put(buf)

	buf.Reset()
	size := len(bin)

	buf.WriteByte(byte(t))
	buf.WriteByte(byte(size >> 8))
	buf.WriteByte(byte(size & 0xFF))
	buf.Write(bin)
	return buf.Bytes()
}

func end() []byte {
	return []byte{byte(END)}
}

func stringToBytes(s string) []byte {
	bin := make([]byte, 4)
	encoded := []byte{}

	for _, r := range []rune(s) {
		n := utf8.EncodeRune(bin, r)
		encoded = append(encoded, bin[:n]...)
	}

	return encoded
}

func packIdent(s string) []byte {
	return pack(IDENT_VALUE, stringToBytes(s))
}

func packString(s string) []byte {
	return pack(STRING_VALUE, stringToBytes(s))
}

func packRTime(s string) []byte {
	return pack(RTIME_VALUE, stringToBytes(s))
}

func packIP(s string) []byte {
	return pack(IP_VALUE, stringToBytes(s))
}

func packInteger(i int64) []byte {
	bin := make([]byte, 8)
	binary.BigEndian.PutUint64(bin, uint64(i))

	return pack(INTEGER_VALUE, bin)
}

func packFloat(f float64) []byte {
	bin := make([]byte, 8)
	binary.BigEndian.PutUint64(bin, math.Float64bits(f))

	return pack(FLOAT_VALUE, bin)
}

func packBoolean(b bool) []byte {
	v := byte(0x00)
	if b {
		v = byte(0x01)
	}

	return pack(BOOL_VALUE, []byte{v})
}
