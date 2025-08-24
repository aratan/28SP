package onion

import (
	"testing"
)

func TestInitKeySystem(t *testing.T) {
	err := InitKeySystem()
	if err != nil {
		t.Fatalf("Failed to initialize key system: %v", err)
	}

	if NodeID == "" {
		t.Error("NodeID should not be empty after initialization")
	}

	if NodePrivateKey == nil {
		t.Error("NodePrivateKey should not be nil after initialization")
	}
}

func TestSelectRandomRoute(t *testing.T) {
	// Initialize the key system first
	if err := InitKeySystem(); err != nil {
		t.Fatalf("Failed to initialize key system: %v", err)
	}

	// Add a mock node to test with
	mockKey := NodePrivateKey

	KnownNodesMutex.Lock()
	KnownNodes["test-node-1"] = &OnionNode{
		ID:        "test-node-1",
		PublicKey: &mockKey.PublicKey,
	}
	KnownNodes["test-node-2"] = &OnionNode{
		ID:        "test-node-2",
		PublicKey: &mockKey.PublicKey,
	}
	KnownNodesMutex.Unlock()

	// Test with minHops=1, maxHops=2
	route, err := SelectRandomRoute(1, 2)
	if err != nil {
		t.Fatalf("Failed to select random route: %v", err)
	}

	if len(route) < 1 || len(route) > 2 {
		t.Errorf("Route length should be between 1 and 2, got %d", len(route))
	}

	// Test with minHops=2, maxHops=2 (exact)
	route, err = SelectRandomRoute(2, 2)
	if err != nil {
		t.Fatalf("Failed to select random route: %v", err)
	}

	if len(route) != 2 {
		t.Errorf("Route length should be exactly 2, got %d", len(route))
	}
}