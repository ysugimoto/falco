package codec

import (
	"unicode/utf8"
)

func stringToBytes(s string) []byte {
	bin := make([]byte, 4)
	encoded := []byte{}

	for _, r := range s {
		n := utf8.EncodeRune(bin, r)
		encoded = append(encoded, bin[:n]...)
	}

	return encoded
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

func end() []byte {
	return []byte{byte(END)}
}

func fin() []byte {
	return []byte{byte(FIN)}
}

func isExpressionFrame(f *Frame) bool {
	switch f.Type() {
	case GROUPED_EXPRESSION,
		INFIX_EXPRESSION,
		POSTFIX_EXPRESSION,
		PREFIX_EXPRESSION,
		IF_EXPRESSION,
		FUNCTIONCALL_EXPRESSION,
		FLOAT_VALUE,
		IP_VALUE,
		IDENT_VALUE,
		BOOL_VALUE,
		INTEGER_VALUE,
		RTIME_VALUE,
		STRING_VALUE:

		return true
	}

	return false
}
