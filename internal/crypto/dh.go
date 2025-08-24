package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// DiffieHellman represents a Diffie-Hellman key exchange instance
type DiffieHellman struct {
	p *big.Int // Prime modulus
	g *big.Int // Base generator
	privateKey *big.Int
	publicKey *big.Int
}

// NewDiffieHellman creates a new Diffie-Hellman instance with standard parameters
func NewDiffieHellman() (*DiffieHellman, error) {
	// Using a standard 2048-bit safe prime for Diffie-Hellman
	// In practice, you might want to use a well-known prime from RFCs
	p, success := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	if !success {
		return nil, fmt.Errorf("failed to parse prime")
	}
	
	// Generator g = 2
	g := big.NewInt(2)
	
	// Generate private key (random number < p-1)
	privateKey, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(1)))
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	
	// Calculate public key: g^privateKey mod p
	publicKey := new(big.Int).Exp(g, privateKey, p)
	
	return &DiffieHellman{
		p: p,
		g: g,
		privateKey: privateKey,
		publicKey: publicKey,
	}, nil
}

// GetPublicKey returns the public key for sharing
func (dh *DiffieHellman) GetPublicKey() *big.Int {
	return new(big.Int).Set(dh.publicKey)
}

// ComputeSharedSecret computes the shared secret using the other party's public key
func (dh *DiffieHellman) ComputeSharedSecret(otherPublicKey *big.Int) ([]byte, error) {
	if otherPublicKey == nil {
		return nil, fmt.Errorf("other public key is nil")
	}
	
	// Check that otherPublicKey < p
	if otherPublicKey.Cmp(dh.p) >= 0 {
		return nil, fmt.Errorf("other public key is too large")
	}
	
	// Calculate shared secret: otherPublicKey^privateKey mod p
	sharedSecret := new(big.Int).Exp(otherPublicKey, dh.privateKey, dh.p)
	
	// Convert to bytes and hash to get a fixed-length key
	secretBytes := sharedSecret.Bytes()
	hash := sha256.Sum256(secretBytes)
	
	return hash[:], nil
}

// GenerateKeyPair generates a new Diffie-Hellman key pair
func GenerateKeyPair() (privateKey, publicKey *big.Int, err error) {
	dh, err := NewDiffieHellman()
	if err != nil {
		return nil, nil, err
	}
	
	return new(big.Int).Set(dh.privateKey), new(big.Int).Set(dh.publicKey), nil
}

// DeriveSharedSecret derives a shared secret from a private key and another party's public key
func DeriveSharedSecret(privateKey, otherPublicKey *big.Int) ([]byte, error) {
	dh, err := NewDiffieHellman()
	if err != nil {
		return nil, err
	}
	
	// Set our private key
	dh.privateKey = new(big.Int).Set(privateKey)
	
	// Calculate our public key
	dh.publicKey = new(big.Int).Exp(dh.g, dh.privateKey, dh.p)
	
	return dh.ComputeSharedSecret(otherPublicKey)
}