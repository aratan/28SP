package cache

import (
	"sync"
	"time"
)

// MessageCache represents a cache for P2P messages
type MessageCache struct {
	cache    map[string]*CacheEntry
	mutex    sync.RWMutex
	maxSize  int
	expiry   time.Duration
}

// CacheEntry represents a cached message
type CacheEntry struct {
	Message   interface{}
	Timestamp time.Time
}

// NewMessageCache creates a new message cache
func NewMessageCache(maxSize int, expiry time.Duration) *MessageCache {
	return &MessageCache{
		cache:   make(map[string]*CacheEntry),
		maxSize: maxSize,
		expiry:  expiry,
	}
}

// Get retrieves a message from the cache
func (mc *MessageCache) Get(key string) (interface{}, bool) {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	
	entry, exists := mc.cache[key]
	if !exists {
		return nil, false
	}
	
	// Check if entry has expired
	if time.Since(entry.Timestamp) > mc.expiry {
		// Entry expired, remove it
		go mc.remove(key)
		return nil, false
	}
	
	return entry.Message, true
}

// Put adds a message to the cache
func (mc *MessageCache) Put(key string, message interface{}) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	// Check if cache is at maximum size
	if len(mc.cache) >= mc.maxSize {
		// Remove the oldest entry
		oldestKey := ""
		var oldestTime time.Time
		for k, entry := range mc.cache {
			if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
				oldestKey = k
				oldestTime = entry.Timestamp
			}
		}
		if oldestKey != "" {
			delete(mc.cache, oldestKey)
		}
	}
	
	// Add the new entry
	mc.cache[key] = &CacheEntry{
		Message:   message,
		Timestamp: time.Now(),
	}
}

// Remove removes a message from the cache
func (mc *MessageCache) remove(key string) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	delete(mc.cache, key)
}

// Remove removes a message from the cache (public method)
func (mc *MessageCache) Remove(key string) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	delete(mc.cache, key)
}

// Contains checks if a message exists in the cache
func (mc *MessageCache) Contains(key string) bool {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	
	_, exists := mc.cache[key]
	return exists
}

// Size returns the current size of the cache
func (mc *MessageCache) Size() int {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	
	return len(mc.cache)
}

// Clear removes all entries from the cache
func (mc *MessageCache) Clear() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	mc.cache = make(map[string]*CacheEntry)
}

// CleanupExpired removes all expired entries from the cache
func (mc *MessageCache) CleanupExpired() int {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	now := time.Now()
	count := 0
	
	for key, entry := range mc.cache {
		if now.Sub(entry.Timestamp) > mc.expiry {
			delete(mc.cache, key)
			count++
		}
	}
	
	return count
}

// GetStats returns cache statistics
func (mc *MessageCache) GetStats() map[string]interface{} {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	
	expiredCount := 0
	now := time.Now()
	
	for _, entry := range mc.cache {
		if now.Sub(entry.Timestamp) > mc.expiry {
			expiredCount++
		}
	}
	
	return map[string]interface{}{
		"size":         len(mc.cache),
		"maxSize":      mc.maxSize,
		"expiredCount": expiredCount,
		"expiry":       mc.expiry.String(),
	}
}