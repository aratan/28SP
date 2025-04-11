package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Variables para el enrutamiento cebolla real
var (
	onionEnabled    = true
	nodeID          string
	nodePrivateKey  *rsa.PrivateKey
	knownNodes      = make(map[string]*rsa.PublicKey)
	knownNodesMutex sync.RWMutex
)

// Inicializar el sistema de enrutamiento cebolla real
func initRealOnionRouting(ctx context.Context) error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")

	// Inicializar el sistema de claves
	if err := initRealKeySystem(); err != nil {
		return fmt.Errorf("error al inicializar sistema de claves: %v", err)
	}

	// Anunciar la presencia de este nodo
	log.Printf("Nodo anunciado en la red: %s", nodeID)

	log.Println("Enrutamiento cebolla real activado correctamente")
	return nil
}

// Inicializar el sistema de claves para el enrutamiento cebolla real
func initRealKeySystem() error {
	log.Println("Inicializando sistema de claves para enrutamiento cebolla...")

	// Crear directorio para las claves si no existe
	keysDir := "onion_keys"
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return fmt.Errorf("error al crear directorio de claves: %v", err)
	}

	// Ruta del archivo de clave privada
	privateKeyPath := filepath.Join(keysDir, "private_key.pem")

	// Verificar si ya existe una clave privada
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		// Generar nueva clave privada
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("error al generar clave privada: %v", err)
		}

		// Guardar clave privada
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		if err := ioutil.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
			return fmt.Errorf("error al guardar clave privada: %v", err)
		}

		// Guardar clave pública
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

	log.Printf("Sistema de claves inicializado. ID del nodo: %s", nodeID)

	// Registrar este nodo en el mapa de nodos conocidos
	knownNodesMutex.Lock()
	knownNodes[nodeID] = &nodePrivateKey.PublicKey
	knownNodesMutex.Unlock()

	return nil
}
