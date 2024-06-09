package codec

import "testing"

func TestASType(t *testing.T) {
	if VCL != 56 {
		t.Errorf("VCL constant must be 56, actual %d", VCL)
	}
}
