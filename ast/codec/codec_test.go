package codec

import "testing"

func TestASType(t *testing.T) {
	if VCL != 55 {
		t.Errorf("VCL constant must be 55, actual %d", VCL)
	}
}
