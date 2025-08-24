package crypto

import (
	"testing"
)

func TestComputeAndVerifyMAC(t *testing.T) {
	message := []byte("test message")
	key := []byte("test key")

	// Compute MAC
	mac := ComputeMAC(message, key)

	if mac == "" {
		t.Error("MAC should not be empty")
	}

	// Verify MAC
	valid, err := VerifyMAC(message, mac, key)
	if err != nil {
		t.Fatalf("Failed to verify MAC: %v", err)
	}

	if !valid {
		t.Error("MAC should be valid")
	}

	// Test with wrong key
	valid, err = VerifyMAC(message, mac, []byte("wrong key"))
	if err != nil {
		t.Fatalf("Failed to verify MAC with wrong key: %v", err)
	}

	if valid {
		t.Error("MAC should be invalid with wrong key")
	}

	// Test with wrong message
	valid, err = VerifyMAC([]byte("wrong message"), mac, key)
	if err != nil {
		t.Fatalf("Failed to verify MAC with wrong message: %v", err)
	}

	if valid {
		t.Error("MAC should be invalid with wrong message")
	}
}

func TestAddAndVerifyMAC(t *testing.T) {
	message := []byte("test message")
	key := []byte("test key")

	// Add MAC
	msgWithMAC, mac := AddMAC(message, key)

	if mac == "" {
		t.Error("MAC should not be empty")
	}

	// Verify MAC
	valid, err := VerifyMAC(msgWithMAC, mac, key)
	if err != nil {
		t.Fatalf("Failed to verify MAC: %v", err)
	}

	if !valid {
		t.Error("MAC should be valid")
	}
}