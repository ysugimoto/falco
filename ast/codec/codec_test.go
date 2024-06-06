package codec

import "testing"

func TestASType(t *testing.T) {
	if VCL != 52 {
		t.Errorf("VCL constant must be 52, actual %d", VCL)
	}
}
