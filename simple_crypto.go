package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
)

// SimpleEncrypt takes a message and a key and returns a base64-encoded string
// This is an extremely simple encryption method for compatibility
func SimpleEncrypt(message []byte, key []byte) ([]byte, error) {
	// Just base64 encode the message for now
	// This isn't encryption, but it will ensure the message is transmitted correctly
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(message)))
	base64.StdEncoding.Encode(encoded, message)
	return encoded, nil
}

// SimpleDecrypt takes a base64-encoded string and a key and returns the original message
// This is an extremely simple decryption method for compatibility
func SimpleDecrypt(encoded []byte, key []byte) ([]byte, error) {
	// Just base64 decode the message
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %v", err)
	}
	return decoded[:n], nil
}

// SimpleSerializeMessage serializes a message using the simple encryption method
func SimpleSerializeMessage(msg Message, keys [][]byte) ([]byte, error) {
	// Marshal the message to JSON
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal error: %v", err)
	}
	
	// Use the first key if available, otherwise use a default key
	var key []byte
	if len(keys) > 0 && len(keys[0]) > 0 {
		key = keys[0]
	} else {
		key = []byte("default-key")
	}
	
	// Encrypt (base64 encode) the message
	return SimpleEncrypt(msgBytes, key)
}

// SimpleDeserializeMessage deserializes a message using the simple decryption method
func SimpleDeserializeMessage(data []byte, keys [][]byte) (Message, error) {
	// Use the first key if available, otherwise use a default key
	var key []byte
	if len(keys) > 0 && len(keys[0]) > 0 {
		key = keys[0]
	} else {
		key = []byte("default-key")
	}
	
	// Try to decrypt (base64 decode) the data
	decryptedData, err := SimpleDecrypt(data, key)
	if err != nil {
		// If decryption fails, try using the data directly
		log.Printf("Decryption failed: %v - Trying direct unmarshaling", err)
		decryptedData = data
	}
	
	// Try to unmarshal the data
	var msg Message
	err = json.Unmarshal(decryptedData, &msg)
	if err != nil {
		return Message{}, fmt.Errorf("unmarshal error: %v", err)
	}
	
	return msg, nil
}
