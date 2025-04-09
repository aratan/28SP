package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// Inicializar el sistema de claves para el enrutamiento cebolla
func InitKeySystem() error {
	log.Println("Inicializando sistema de claves para enrutamiento cebolla...")

	// Crear directorio para claves si no existe
	keysDir := "onion_keys"
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return fmt.Errorf("error al crear directorio para claves: %v", err)
	}

	// Comprobar si ya tenemos una clave privada
	privateKeyPath := filepath.Join(keysDir, "private_key.pem")
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		// Generar un nuevo par de claves RSA
		log.Println("Generando nuevo par de claves RSA...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("error al generar clave RSA: %v", err)
		}

		// Guardar la clave privada
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		if err := ioutil.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
			return fmt.Errorf("error al guardar clave privada: %v", err)
		}

		// Guardar la clave pública
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("error al serializar clave pública: %v", err)
		}

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		publicKeyPath := filepath.Join(keysDir, "public_key.pem")
		if err := ioutil.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
			return fmt.Errorf("error al guardar clave pública: %v", err)
		}

		NodePrivateKey = privateKey
	} else {
		// Cargar clave privada existente
		log.Println("Cargando clave privada existente...")
		privateKeyPEM, err := ioutil.ReadFile(privateKeyPath)
		if err != nil {
			return fmt.Errorf("error al leer clave privada: %v", err)
		}

		block, _ := pem.Decode(privateKeyPEM)
		if block == nil {
			return fmt.Errorf("error al decodificar clave privada PEM")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("error al parsear clave privada: %v", err)
		}

		NodePrivateKey = privateKey
	}

	// Calcular el ID del nodo a partir de la clave pública
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&NodePrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error al serializar clave pública: %v", err)
	}

	hash := sha256.Sum256(publicKeyBytes)
	NodeID = fmt.Sprintf("%x", hash[:8])

	// Registrar este nodo en el mapa de nodos conocidos
	KnownNodesMutex.Lock()
	KnownNodes[NodeID] = &NodePrivateKey.PublicKey
	KnownNodesMutex.Unlock()

	log.Printf("Sistema de claves inicializado. ID del nodo: %s", NodeID)
	return nil
}

// Cifrar datos con AES-GCM
func EncryptLayer(data []byte, key []byte) ([]byte, error) {
	// Asegurar que la clave tenga el tamaño correcto para AES-256
	hashedKey := sha256.Sum256(key)

	// Crear el cifrador AES
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	// Generar un nonce aleatorio
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Crear el modo GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Cifrar los datos
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	// Concatenar nonce y ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Descifrar datos con AES-GCM
func DecryptLayer(data []byte, key []byte) ([]byte, error) {
	// Asegurar que la clave tenga el tamaño correcto para AES-256
	hashedKey := sha256.Sum256(key)

	// Verificar que los datos tengan al menos el tamaño del nonce
	if len(data) < 12 {
		return nil, fmt.Errorf("datos demasiado cortos")
	}

	// Extraer el nonce
	nonce := data[:12]
	ciphertext := data[12:]

	// Crear el cifrador AES
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	// Crear el modo GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Descifrar los datos
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Cifrar datos con RSA-OAEP
func EncryptWithRSA(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
}

// Descifrar datos con RSA-OAEP
func DecryptWithRSA(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, data, nil)
}

// Convertir clave pública a string
func PublicKeyToString(publicKey *rsa.PublicKey) string {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Printf("Error al serializar clave pública: %v", err)
		return ""
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return base64.StdEncoding.EncodeToString(publicKeyPEM)
}

// Convertir string a clave pública
func StringToPublicKey(publicKeyStr string) (*rsa.PublicKey, error) {
	publicKeyPEM, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("error al decodificar clave pública: %v", err)
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("error al decodificar clave pública PEM")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error al parsear clave pública: %v", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("clave pública no es de tipo RSA")
	}

	return publicKey, nil
}
