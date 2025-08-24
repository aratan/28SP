package cache

import (
	"testing"
	"time"
)

func TestMessageCache(t *testing.T) {
	// Create a new message cache with capacity 2 and 1 second expiry
	cache := NewMessageCache(2, time.Second)

	if cache == nil {
		t.Fatal("Failed to create message cache")
	}
}

func TestPutAndGet(t *testing.T) {
	cache := NewMessageCache(2, time.Second)

	// Put a message in the cache
	cache.Put("key1", "message1")

	// Get the message from the cache
	message, exists := cache.Get("key1")
	if !exists {
		t.Error("Expected message to exist in cache")
	}

	if message != "message1" {
		t.Errorf("Expected 'message1', got '%v'", message)
	}

	// Try to get a non-existent message
	_, exists = cache.Get("key2")
	if exists {
		t.Error("Expected message to not exist in cache")
	}
}

func TestRemove(t *testing.T) {
	cache := NewMessageCache(2, time.Second)

	// Put a message in the cache
	cache.Put("key1", "message1")

	// Remove the message
	cache.Remove("key1")

	// Try to get the removed message
	_, exists := cache.Get("key1")
	if exists {
		t.Error("Expected message to not exist in cache after removal")
	}
}

func TestSize(t *testing.T) {
	cache := NewMessageCache(2, time.Second)

	// Check initial size
	if cache.Size() != 0 {
		t.Errorf("Expected size 0, got %d", cache.Size())
	}

	// Put a message in the cache
	cache.Put("key1", "message1")

	// Check size after adding one message
	if cache.Size() != 1 {
		t.Errorf("Expected size 1, got %d", cache.Size())
	}

	// Put another message in the cache
	cache.Put("key2", "message2")

	// Check size after adding two messages
	if cache.Size() != 2 {
		t.Errorf("Expected size 2, got %d", cache.Size())
	}
}

func TestContains(t *testing.T) {
	cache := NewMessageCache(2, time.Second)

	// Check if non-existent key is contained
	if cache.Contains("key1") {
		t.Error("Expected key1 to not be contained in empty cache")
	}

	// Put a message in the cache
	cache.Put("key1", "message1")

	// Check if key is contained
	if !cache.Contains("key1") {
		t.Error("Expected key1 to be contained in cache")
	}
}

func TestClear(t *testing.T) {
	cache := NewMessageCache(2, time.Second)

	// Put messages in the cache
	cache.Put("key1", "message1")
	cache.Put("key2", "message2")

	// Clear the cache
	cache.Clear()

	// Check that cache is empty
	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", cache.Size())
	}

	// Check that keys don't exist
	if cache.Contains("key1") {
		t.Error("Expected key1 to not exist after clear")
	}

	if cache.Contains("key2") {
		t.Error("Expected key2 to not exist after clear")
	}
}