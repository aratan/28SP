package onion

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// OnionNode represents a node in the onion routing network
type OnionNode struct {
	ID        string
	PublicKey *rsa.PublicKey
	LastSeen  time.Time
}

// OnionMessage represents a message with onion routing layers
type OnionMessage struct {
	Type        string          `json:"type"`
	CurrentHop  string          `json:"currentHop"`
	Payload     json.RawMessage `json:"payload"`
	Destination string          `json:"destination"`
}

// Global variables for known nodes and current node ID
var (
	KnownNodes      = make(map[string]*OnionNode)
	KnownNodesMutex = sync.RWMutex{}
	NodeID          string
	NodePrivateKey  *rsa.PrivateKey
)

// InitKeySystem initializes the key system for the current node
func InitKeySystem() error {
	// Generate private key for this node
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	NodePrivateKey = privateKey

	// Generate node ID based on public key hash
	publicKeyBytes, err := json.Marshal(privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	hash := sha256.Sum256(publicKeyBytes)
	NodeID = fmt.Sprintf("node-%x", hash[:16])

	log.Printf("Onion routing system initialized. Node ID: %s", NodeID)
	return nil
}

// SelectRandomRoute selects a random route through known nodes
func SelectRandomRoute(minHops, maxHops int) ([]string, error) {
	KnownNodesMutex.RLock()
	defer KnownNodesMutex.RUnlock()

	// Check if we have enough nodes
	if len(KnownNodes) < minHops {
		return nil, fmt.Errorf("not enough known nodes for routing")
	}

	// Determine number of hops
	numHops := minHops
	if maxHops > minHops {
		// Generate random number between minHops and maxHops
		diff := maxHops - minHops
		randomBytes := make([]byte, 1)
		_, err := rand.Read(randomBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random number: %v", err)
		}
		numHops = minHops + int(randomBytes[0])%diff
	}

	// Select random nodes for the route
	route := make([]string, numHops)
	i := 0
	for nodeID := range KnownNodes {
		if i >= numHops {
			break
		}
		route[i] = nodeID
		i++
	}

	return route, nil
}

// CreateOnionRoutedMessage creates a message with onion routing layers
func CreateOnionRoutedMessage(payload interface{}, route []string) ([]byte, error) {
	// Convert payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Start with the final payload
	currentLayer := payloadBytes

	// Wrap the payload in layers, from innermost to outermost
	for i := len(route) - 1; i >= 0; i-- {
		nodeID := route[i]
		
		// Get the node's public key
		KnownNodesMutex.RLock()
		node, exists := KnownNodes[nodeID]
		KnownNodesMutex.RUnlock()
		
		if !exists {
			return nil, fmt.Errorf("unknown node in route: %s", nodeID)
		}

		// Encrypt the current layer with the node's public key
		encryptedLayer, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, node.PublicKey, currentLayer, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt layer for node %s: %v", nodeID, err)
		}

		// Create onion message for this layer
		onionMsg := OnionMessage{
			Type:        "onion",
			CurrentHop:  nodeID,
			Payload:     encryptedLayer,
			Destination: route[len(route)-1], // Final destination
		}

		// Marshal the onion message
		currentLayer, err = json.Marshal(onionMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal onion message: %v", err)
		}
	}

	return currentLayer, nil
}

// ProcessOnionLayer processes one layer of an onion-routed message
func ProcessOnionLayer(encryptedMessage []byte) ([]byte, string, error) {
	// Decrypt the message with our private key
	var onionMsg OnionMessage
	err := json.Unmarshal(encryptedMessage, &onionMsg)
	if err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal onion message: %v", err)
	}

	if onionMsg.Type != "onion" {
		return nil, "", fmt.Errorf("not an onion message")
	}

	// Decrypt the payload
	decryptedPayload, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, NodePrivateKey, onionMsg.Payload, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt payload: %v", err)
	}

	// Check if this is the final destination
	if onionMsg.Destination == NodeID {
		return decryptedPayload, "", nil // Empty nextHop indicates final destination
	}

	// Not the final destination, return decrypted payload and next hop
	return decryptedPayload, onionMsg.Destination, nil
}

// AddNode adds a new node to the known nodes list
func AddNode(nodeID string, publicKey *rsa.PublicKey) {
	KnownNodesMutex.Lock()
	defer KnownNodesMutex.Unlock()

	KnownNodes[nodeID] = &OnionNode{
		ID:        nodeID,
		PublicKey: publicKey,
		LastSeen:  time.Now(),
	}
}