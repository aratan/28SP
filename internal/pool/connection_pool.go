package pool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ConnectionPool manages a pool of libp2p connections
type ConnectionPool struct {
	host      host.Host
	pool      map[peer.ID][]network.Conn
	mutex     sync.RWMutex
	maxConns  int
	maxIdle   time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(h host.Host, maxConns int, maxIdle time.Duration) *ConnectionPool {
	ctx, cancel := context.WithCancel(context.Background())
	
	cp := &ConnectionPool{
		host:     h,
		pool:     make(map[peer.ID][]network.Conn),
		maxConns: maxConns,
		maxIdle:  maxIdle,
		ctx:      ctx,
		cancel:   cancel,
	}
	
	// Start cleanup goroutine
	go cp.cleanupLoop()
	
	return cp
}

// GetConnection gets a connection to a peer, either from the pool or by creating a new one
func (cp *ConnectionPool) GetConnection(peerID peer.ID) (network.Conn, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	
	// Check if we have an available connection in the pool
	if conns, exists := cp.pool[peerID]; exists && len(conns) > 0 {
		// Take the last connection from the pool
		conn := conns[len(conns)-1]
		cp.pool[peerID] = conns[:len(conns)-1]
		
		// Verify the connection is still alive
		if cp.isConnectionAlive(conn) {
			return conn, nil
		}
		
		// Connection is dead, close it
		conn.Close()
	}
	
	// No available connection in pool, create a new one
	conn, err := cp.host.Network().DialPeer(cp.ctx, peerID)
	if err != nil {
		return nil, fmt.Errorf("failed to dial peer: %v", err)
	}
	
	return conn, nil
}

// ReleaseConnection returns a connection to the pool
func (cp *ConnectionPool) ReleaseConnection(conn network.Conn) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	
	// Don't pool closed connections
	if conn.IsClosed() {
		return
	}
	
	peerID := conn.RemotePeer()
	
	// Check if we've reached the maximum number of connections for this peer
	if len(cp.pool[peerID]) >= cp.maxConns {
		// Close the connection instead of pooling it
		conn.Close()
		return
	}
	
	// Add the connection to the pool
	cp.pool[peerID] = append(cp.pool[peerID], conn)
}

// CloseConnection closes a connection instead of returning it to the pool
func (cp *ConnectionPool) CloseConnection(conn network.Conn) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	
	// Remove the connection from the pool if it's there
	peerID := conn.RemotePeer()
	if conns, exists := cp.pool[peerID]; exists {
		for i, c := range conns {
			if c == conn {
				// Remove the connection from the slice
				cp.pool[peerID] = append(conns[:i], conns[i+1:]...)
				break
			}
		}
	}
	
	// Close the connection
	conn.Close()
}

// isConnectionAlive checks if a connection is still alive
func (cp *ConnectionPool) isConnectionAlive(conn network.Conn) bool {
	// Check if the connection is closed
	if conn.IsClosed() {
		return false
	}
	
	// Try to get the connection stats
	_ = conn.Stat()
	
	// If we get here, the connection is likely alive
	return true
}

// cleanupLoop periodically cleans up idle connections
func (cp *ConnectionPool) cleanupLoop() {
	ticker := time.NewTicker(cp.maxIdle / 2)
	defer ticker.Stop()
	
	for {
		select {
		case <-cp.ctx.Done():
			// Context cancelled, cleanup and exit
			cp.cleanupAll()
			return
		case <-ticker.C:
			// Cleanup idle connections
			cp.cleanupIdle()
		}
	}
}

// cleanupIdle removes idle connections from the pool
func (cp *ConnectionPool) cleanupIdle() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	
	for peerID, conns := range cp.pool {
		// Filter out idle connections
		activeConns := make([]network.Conn, 0, len(conns))
		
		for _, conn := range conns {
			// Check if connection is idle
			if cp.isConnectionAlive(conn) {
				activeConns = append(activeConns, conn)
			} else {
				// Close idle connection
				conn.Close()
			}
		}
		
		// Update the pool with active connections
		if len(activeConns) > 0 {
			cp.pool[peerID] = activeConns
		} else {
			// Remove the entry if no connections remain
			delete(cp.pool, peerID)
		}
	}
}

// cleanupAll closes all connections in the pool
func (cp *ConnectionPool) cleanupAll() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	
	for _, conns := range cp.pool {
		for _, conn := range conns {
			conn.Close()
		}
	}
	
	cp.pool = make(map[peer.ID][]network.Conn)
}

// Close shuts down the connection pool
func (cp *ConnectionPool) Close() error {
	cp.cancel()
	return nil
}

// GetPoolStats returns statistics about the connection pool
func (cp *ConnectionPool) GetPoolStats() map[string]interface{} {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	
	totalConns := 0
	for _, conns := range cp.pool {
		totalConns += len(conns)
	}
	
	return map[string]interface{}{
		"totalConnections": totalConns,
		"peerCount":        len(cp.pool),
		"maxConnections":   cp.maxConns,
		"maxIdleTime":      cp.maxIdle.String(),
	}
}