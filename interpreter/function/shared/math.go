package shared

import "math"

func IsSubnormalFloat64(v float64) bool {
	bits := math.Float64bits(v)
	sign := bits >> 63
	exp := (bits >> 53) & 0x7F
	frac := bits & 0xFFFFFFFFFFFFF

	// In IEEE754,  denormalized number is exp = zero and fraction is not zero
	return exp == 0 && frac != 0 && sign == 0
}

func IsNegativeZero(v float64) bool {
	if v != 0 {
		return false
	}
	bits := math.Float64bits(v)
	return bits>>63 == 1
}

func IsPositiveZero(v float64) bool {
	if v != 0 {
		return false
	}
	bits := math.Float64bits(v)
	return bits>>63 == 0
}
