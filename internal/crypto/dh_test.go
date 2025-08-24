package crypto

import (
	"testing"
)

func TestDiffieHellman(t *testing.T) {
	// Test creating a new Diffie-Hellman instance
	dh, err := NewDiffieHellman()
	if err != nil {
		t.Fatalf("Failed to create Diffie-Hellman instance: %v", err)
	}

	if dh.p == nil {
		t.Error("Prime modulus should not be nil")
	}

	if dh.g == nil {
		t.Error("Base generator should not be nil")
	}

	if dh.privateKey == nil {
		t.Error("Private key should not be nil")
	}

	if dh.publicKey == nil {
		t.Error("Public key should not be nil")
	}

	// Test getting the public key
	publicKey := dh.GetPublicKey()
	if publicKey == nil {
		t.Error("GetPublicKey should not return nil")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	// Create two Diffie-Hellman instances
	dh1, err := NewDiffieHellman()
	if err != nil {
		t.Fatalf("Failed to create first Diffie-Hellman instance: %v", err)
	}

	dh2, err := NewDiffieHellman()
	if err != nil {
		t.Fatalf("Failed to create second Diffie-Hellman instance: %v", err)
	}

	// Compute shared secrets
	sharedSecret1, err := dh1.ComputeSharedSecret(dh2.GetPublicKey())
	if err != nil {
		t.Fatalf("Failed to compute shared secret for dh1: %v", err)
	}

	sharedSecret2, err := dh2.ComputeSharedSecret(dh1.GetPublicKey())
	if err != nil {
		t.Fatalf("Failed to compute shared secret for dh2: %v", err)
	}

	// The shared secrets should be identical
	if len(sharedSecret1) != len(sharedSecret2) {
		t.Errorf("Shared secrets have different lengths: %d vs %d", len(sharedSecret1), len(sharedSecret2))
	}

	for i := range sharedSecret1 {
		if sharedSecret1[i] != sharedSecret2[i] {
			t.Errorf("Shared secrets differ at byte %d: %x vs %x", i, sharedSecret1[i], sharedSecret2[i])
		}
	}
}

func TestGenerateKeyPair(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if privateKey == nil {
		t.Error("Private key should not be nil")
	}

	if publicKey == nil {
		t.Error("Public key should not be nil")
	}
}