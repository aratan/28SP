package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Estructura para representar un nodo en la red
type OnionNode struct {
	ID        string         // ID del nodo (derivado de la clave pública)
	PublicKey *rsa.PublicKey // Clave pública del nodo
	LastSeen  time.Time      // Última vez que se vio al nodo
}

// Variables globales para la gestión de claves
var (
	// Clave privada de este nodo
	nodePrivateKey *rsa.PrivateKey

	// ID de este nodo (derivado de la clave pública)
	nodeID string

	// Mapa de nodos conocidos (ID -> OnionNode)
	knownNodes      = make(map[string]OnionNode)
	knownNodesMutex sync.RWMutex
)

// Inicializar el sistema de gestión de claves
func initKeyManagement() error {
	log.Println("Inicializando sistema de gestión de claves para enrutamiento cebolla...")

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

		nodePrivateKey = privateKey
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

		nodePrivateKey = privateKey
	}

	// Calcular el ID del nodo a partir de la clave pública
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&nodePrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error al serializar clave pública: %v", err)
	}

	hash := sha256.Sum256(publicKeyBytes)
	nodeID = fmt.Sprintf("%x", hash[:8])

	log.Printf("ID del nodo: %s", nodeID)

	// Registrar este nodo en el mapa de nodos conocidos
	knownNodesMutex.Lock()
	knownNodes[nodeID] = OnionNode{
		ID:        nodeID,
		PublicKey: &nodePrivateKey.PublicKey,
		LastSeen:  time.Now(),
	}
	knownNodesMutex.Unlock()

	return nil
}

// Anunciar la presencia de este nodo en la red
func announceNode() error {
	// Crear mensaje de anuncio
	announcement := map[string]interface{}{
		"type":      "node_announcement",
		"nodeID":    nodeID,
		"publicKey": publicKeyToString(&nodePrivateKey.PublicKey),
		"timestamp": time.Now().Unix(),
	}

	// Serializar y publicar
	announcementBytes, err := json.Marshal(announcement)
	if err != nil {
		return fmt.Errorf("error al serializar anuncio: %v", err)
	}

	// Publicar usando el topic P2P existente
	err = p2pTopic.Publish(ctx, announcementBytes)
	if err != nil {
		return fmt.Errorf("error al anunciar nodo: %v", err)
	}

	log.Printf("Nodo anunciado en la red: %s", nodeID)
	return nil
}

// Convertir clave pública a string
func publicKeyToString(publicKey *rsa.PublicKey) string {
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
func stringToPublicKey(publicKeyStr string) (*rsa.PublicKey, error) {
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

// Procesar un anuncio de nodo
func processNodeAnnouncement(data []byte) error {
	var announcement map[string]interface{}
	if err := json.Unmarshal(data, &announcement); err != nil {
		return fmt.Errorf("error al decodificar anuncio: %v", err)
	}

	// Verificar que sea un anuncio de nodo
	msgType, ok := announcement["type"].(string)
	if !ok || msgType != "node_announcement" {
		return fmt.Errorf("no es un anuncio de nodo válido")
	}

	// Extraer ID del nodo
	nodeID, ok := announcement["nodeID"].(string)
	if !ok {
		return fmt.Errorf("anuncio sin ID de nodo")
	}

	// Extraer clave pública
	publicKeyStr, ok := announcement["publicKey"].(string)
	if !ok {
		return fmt.Errorf("anuncio sin clave pública")
	}

	// Convertir clave pública
	publicKey, err := stringToPublicKey(publicKeyStr)
	if err != nil {
		return fmt.Errorf("error al procesar clave pública: %v", err)
	}

	// Registrar el nodo
	knownNodesMutex.Lock()
	knownNodes[nodeID] = OnionNode{
		ID:        nodeID,
		PublicKey: publicKey,
		LastSeen:  time.Now(),
	}
	knownNodesMutex.Unlock()

	log.Printf("Nodo registrado: %s", nodeID)
	return nil
}

// Obtener la clave pública de un nodo
func getNodePublicKey(nodeID string) (*rsa.PublicKey, error) {
	knownNodesMutex.RLock()
	defer knownNodesMutex.RUnlock()

	node, exists := knownNodes[nodeID]
	if !exists {
		return nil, fmt.Errorf("nodo desconocido: %s", nodeID)
	}

	return node.PublicKey, nil
}

// Cifrar datos con la clave pública de un nodo
func encryptForNode(nodeID string, data []byte) ([]byte, error) {
	publicKey, err := getNodePublicKey(nodeID)
	if err != nil {
		return nil, err
	}

	// Usar cifrado híbrido (AES + RSA) para mensajes grandes
	// Generar una clave AES aleatoria
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("error al generar clave AES: %v", err)
	}

	// Cifrar la clave AES con RSA
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error al cifrar clave AES: %v", err)
	}

	// Cifrar los datos con AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("error al crear cifrador AES: %v", err)
	}

	// Generar un nonce aleatorio
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error al generar nonce: %v", err)
	}

	// Crear el modo GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error al crear modo GCM: %v", err)
	}

	// Cifrar los datos
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	// Combinar todo: [longitud de clave cifrada (2 bytes)][clave cifrada][nonce][datos cifrados]
	result := make([]byte, 2+len(encryptedKey)+len(nonce)+len(ciphertext))
	result[0] = byte(len(encryptedKey) >> 8)
	result[1] = byte(len(encryptedKey))
	copy(result[2:], encryptedKey)
	copy(result[2+len(encryptedKey):], nonce)
	copy(result[2+len(encryptedKey)+len(nonce):], ciphertext)

	return result, nil
}

// Descifrar datos con la clave privada de este nodo
func decryptWithNodeKey(data []byte) ([]byte, error) {
	// Extraer la longitud de la clave cifrada
	if len(data) < 2 {
		return nil, fmt.Errorf("datos demasiado cortos")
	}
	keyLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+keyLen+12 {
		return nil, fmt.Errorf("datos demasiado cortos para contener clave y nonce")
	}

	// Extraer la clave cifrada
	encryptedKey := data[2 : 2+keyLen]

	// Extraer el nonce
	nonce := data[2+keyLen : 2+keyLen+12]

	// Extraer los datos cifrados
	ciphertext := data[2+keyLen+12:]

	// Descifrar la clave AES con RSA
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, nodePrivateKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error al descifrar clave AES: %v", err)
	}

	// Descifrar los datos con AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("error al crear cifrador AES: %v", err)
	}

	// Crear el modo GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error al crear modo GCM: %v", err)
	}

	// Descifrar los datos
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error al descifrar datos: %v", err)
	}

	return plaintext, nil
}
