package mtk

import (
	"testing"
)

func TestMachineID(t *testing.T) {
	mid := MachineID()
	if mid == "" {
		t.Fatal("expected a machine ID")
	}
	if len(mid) != 36 {
		t.Fatal("expected a machine ID of 36 characters")
	}
}
