package codec

import "testing"

func TestASType(t *testing.T) {
	if VCL != 50 {
		t.Errorf("VCL constant must be 50, actual %d", VCL)
	}
}
