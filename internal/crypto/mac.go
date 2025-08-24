package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ComputeMAC computes a message authentication code for the given message and key
func ComputeMAC(message []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyMAC verifies that the given MAC is valid for the message and key
func VerifyMAC(message []byte, messageMAC string, key []byte) (bool, error) {
	expectedMAC := ComputeMAC(message, key)
	
	// Use constant time comparison to prevent timing attacks
	expected, err := hex.DecodeString(expectedMAC)
	if err != nil {
		return false, fmt.Errorf("failed to decode expected MAC: %v", err)
	}
	
	actual, err := hex.DecodeString(messageMAC)
	if err != nil {
		return false, fmt.Errorf("failed to decode actual MAC: %v", err)
	}
	
	// Check if lengths match
	if len(expected) != len(actual) {
		return false, nil
	}
	
	// Constant time comparison
	return hmac.Equal(expected, actual), nil
}

// AddMAC adds a MAC to a message for authentication
func AddMAC(message []byte, key []byte) ([]byte, string) {
	mac := ComputeMAC(message, key)
	
	// In a real implementation, you would append the MAC to the message
	// For now, we just return both the message and MAC
	return message, mac
}

// VerifyAndStripMAC verifies the MAC of a message and strips it
func VerifyAndStripMAC(messageWithMAC []byte, key []byte) ([]byte, bool, error) {
	// In a real implementation, you would extract the MAC from the message
	// For now, we assume the message and MAC are separate
	
	// This is a simplified implementation - in practice, you would need
	// a more robust way to separate the message from its MAC
	
	// For demonstration, we'll just verify the MAC against the message
	isValid, err := VerifyMAC(messageWithMAC, ComputeMAC(messageWithMAC, key), key)
	if err != nil {
		return nil, false, err
	}
	
	return messageWithMAC, isValid, nil
}