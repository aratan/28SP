package main

import (
	"context"
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
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Variables globales para el enrutamiento cebolla
var (
	// Mapa de nodos conocidos (ID -> OnionNode)
	knownNodes = make(map[string]OnionNode)
	knownNodesMutex sync.RWMutex

	// Clave privada de este nodo
	nodePrivateKey *rsa.PrivateKey

	// ID de este nodo
	nodeID string
)

// Inicializar el sistema de enrutamiento cebolla
func initOnionRouting() error {
	log.Println("Inicializando sistema de enrutamiento cebolla...")
	
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
	
	// Establecer el ID del nodo (hash de la clave pública)
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
	}
	knownNodesMutex.Unlock()
	
	return nil
}

// Iniciar la escucha de mensajes de enrutamiento cebolla
func startOnionListener() error {
	// Anunciar la presencia de este nodo
	announceNode()
	
	return nil
}

// Anunciar la presencia de este nodo en la red
func announceNode() {
	// Crear mensaje de anuncio
	announcement := map[string]interface{}{
		"type":      "node_announcement",
		"nodeID":    nodeID,
		"publicKey": publicKeyToString(&nodePrivateKey.PublicKey),
		"timestamp": time.Now().Unix(),
	}
	
	// Serializar y publicar
	announcementBytes, _ := json.Marshal(announcement)
	
	// Publicar usando el topic P2P existente
	err := p2pTopic.Publish(context.Background(), announcementBytes)
	if err != nil {
		log.Printf("Error al anunciar nodo: %v", err)
		return
	}
	
	log.Printf("Nodo anunciado en la red: %s", nodeID)
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

// Cifrar datos con una clave pública RSA
func encryptWithPublicKey(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	// En una implementación real, se usaría cifrado híbrido (RSA + AES)
	// Para simplificar, usamos RSA directamente con padding OAEP
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
}

// Descifrar datos con una clave privada RSA
func decryptWithPrivateKey(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	// En una implementación real, se usaría cifrado híbrido (RSA + AES)
	// Para simplificar, usamos RSA directamente con padding OAEP
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, data, nil)
}

// Seleccionar una ruta aleatoria para un mensaje
func selectRandomRoute(minHops, maxHops int) ([]string, error) {
	knownNodesMutex.RLock()
	defer knownNodesMutex.RUnlock()
	
	// Contar nodos disponibles (excluyendo este nodo)
	availableNodes := make([]string, 0, len(knownNodes)-1)
	for id := range knownNodes {
		if id != nodeID {
			availableNodes = append(availableNodes, id)
		}
	}
	
	if len(availableNodes) < minHops {
		return nil, fmt.Errorf("no hay suficientes nodos para crear una ruta (mínimo %d, disponibles %d)", 
			minHops, len(availableNodes))
	}
	
	// Determinar el número de saltos
	numHops := minHops
	if maxHops > minHops {
		extraHops, _ := rand.Int(rand.Reader, big.NewInt(int64(maxHops-minHops+1)))
		numHops += int(extraHops.Int64())
	}
	
	if numHops > len(availableNodes) {
		numHops = len(availableNodes)
	}
	
	// Seleccionar nodos aleatorios para la ruta
	route := make([]string, numHops)
	for i := 0; i < numHops; i++ {
		// Seleccionar un nodo aleatorio de los disponibles
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(availableNodes))))
		route[i] = availableNodes[idx.Int64()]
		
		// Eliminar el nodo seleccionado para evitar repeticiones
		availableNodes = append(availableNodes[:idx.Int64()], availableNodes[idx.Int64()+1:]...)
	}
	
	return route, nil
}
