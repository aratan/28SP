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
	"os"
	"path/filepath"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// Variables globales para el topic de control
var (
	// Topic de control para mensajes de gestión de la red
	controlTopic *pubsub.Topic
	controlSub   *pubsub.Subscription

	// Clave privada de este nodo
	nodePrivateKey *rsa.PrivateKey

	// ID de este nodo (derivado de la clave pública)
	nodeID string

	// Mapa de nodos conocidos (ID -> clave pública)
	knownNodes      = make(map[string]*rsa.PublicKey)
	knownNodesMutex sync.RWMutex

	// Mapa de rutas conocidas (destino -> [nodos intermedios])
	knownRoutes      = make(map[string][]string)
	knownRoutesMutex sync.RWMutex
)

// Tipos de mensajes de control
const (
	MsgTypeNodeAnnouncement = "node_announcement"
	MsgTypeKeyExchange      = "key_exchange"
	MsgTypeRouteUpdate      = "route_update"
	MsgTypeNetworkStatus    = "network_status"
)

// Inicializar el topic de control
func initControlTopic(ctx context.Context) error {
	log.Println("Inicializando topic de control...")

	// Crear el topic de control
	var err error
	controlTopic, err = ps.Join("p2p-control")
	if err != nil {
		return fmt.Errorf("error al unirse al topic de control: %v", err)
	}

	// Suscribirse al topic de control
	controlSub, err = controlTopic.Subscribe()
	if err != nil {
		return fmt.Errorf("error al suscribirse al topic de control: %v", err)
	}

	// Iniciar la escucha de mensajes de control
	go handleControlMessages(ctx)

	log.Println("Topic de control inicializado correctamente")
	return nil
}

// Inicializar el sistema de claves para el enrutamiento cebolla
func initKeySystem() error {
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

	// Registrar este nodo en el mapa de nodos conocidos
	knownNodesMutex.Lock()
	knownNodes[nodeID] = &nodePrivateKey.PublicKey
	knownNodesMutex.Unlock()

	log.Printf("Sistema de claves inicializado. ID del nodo: %s", nodeID)
	return nil
}

// Manejar mensajes del topic de control
func handleControlMessages(ctx context.Context) {
	for {
		msg, err := controlSub.Next(ctx)
		if err != nil {
			log.Printf("Error al recibir mensaje de control: %v", err)
			continue
		}

		// Ignorar mensajes propios
		if msg.ReceivedFrom == host.ID() {
			continue
		}

		// Procesar el mensaje de control
		go processControlMessage(msg.Data)
	}
}

// Procesar un mensaje de control
func processControlMessage(data []byte) {
	// Decodificar el mensaje
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("Error al decodificar mensaje de control: %v", err)
		return
	}

	// Obtener el tipo de mensaje
	msgType, ok := msg["type"].(string)
	if !ok {
		log.Printf("Mensaje de control sin tipo")
		return
	}

	// Procesar según el tipo de mensaje
	switch msgType {
	case MsgTypeNodeAnnouncement:
		processNodeAnnouncement(msg)
	case MsgTypeKeyExchange:
		processKeyExchange(msg)
	case MsgTypeRouteUpdate:
		processRouteUpdate(msg)
	case MsgTypeNetworkStatus:
		processNetworkStatus(msg)
	default:
		log.Printf("Tipo de mensaje de control desconocido: %s", msgType)
	}
}

// Procesar un anuncio de nodo
func processNodeAnnouncement(msg map[string]interface{}) {
	// Extraer ID del nodo
	nodeID, ok := msg["nodeID"].(string)
	if !ok {
		log.Printf("Anuncio de nodo sin ID")
		return
	}

	// Extraer clave pública
	publicKeyStr, ok := msg["publicKey"].(string)
	if !ok {
		log.Printf("Anuncio de nodo sin clave pública")
		return
	}

	// Decodificar la clave pública
	publicKeyPEM, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		log.Printf("Error al decodificar clave pública: %v", err)
		return
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		log.Printf("Error al decodificar clave pública PEM")
		return
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("Error al parsear clave pública: %v", err)
		return
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		log.Printf("Clave pública no es de tipo RSA")
		return
	}

	// Registrar el nodo
	knownNodesMutex.Lock()
	knownNodes[nodeID] = publicKey
	knownNodesMutex.Unlock()

	log.Printf("Nodo registrado: %s", nodeID)
}

// Procesar un intercambio de claves
func processKeyExchange(msg map[string]interface{}) {
	// Implementación del intercambio de claves
	log.Printf("Procesando intercambio de claves")
}

// Procesar una actualización de ruta
func processRouteUpdate(msg map[string]interface{}) {
	// Extraer destino
	dest, ok := msg["destination"].(string)
	if !ok {
		log.Printf("Actualización de ruta sin destino")
		return
	}

	// Extraer ruta
	routeInterface, ok := msg["route"].([]interface{})
	if !ok {
		log.Printf("Actualización de ruta sin ruta")
		return
	}

	// Convertir la ruta a []string
	route := make([]string, len(routeInterface))
	for i, nodeInterface := range routeInterface {
		nodeID, ok := nodeInterface.(string)
		if !ok {
			log.Printf("ID de nodo inválido en ruta")
			return
		}
		route[i] = nodeID
	}

	// Registrar la ruta
	knownRoutesMutex.Lock()
	knownRoutes[dest] = route
	knownRoutesMutex.Unlock()

	log.Printf("Ruta actualizada para destino %s: %v", dest, route)
}

// Procesar un estado de red
func processNetworkStatus(msg map[string]interface{}) {
	// Implementación del procesamiento de estado de red
	log.Printf("Procesando estado de red")
}

// Anunciar la presencia de este nodo en la red
func announceNode() error {
	// Convertir la clave pública a formato PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&nodePrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error al serializar clave pública: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Crear mensaje de anuncio
	announcement := map[string]interface{}{
		"type":      MsgTypeNodeAnnouncement,
		"nodeID":    nodeID,
		"publicKey": base64.StdEncoding.EncodeToString(publicKeyPEM),
		"timestamp": time.Now().Unix(),
	}

	// Serializar y publicar
	announcementBytes, err := json.Marshal(announcement)
	if err != nil {
		return fmt.Errorf("error al serializar anuncio: %v", err)
	}

	// Publicar en el topic de control
	err = controlTopic.Publish(context.Background(), announcementBytes)
	if err != nil {
		return fmt.Errorf("error al anunciar nodo: %v", err)
	}

	log.Printf("Nodo anunciado en la red: %s", nodeID)
	return nil
}

// Publicar una actualización de ruta
func publishRouteUpdate(dest string, route []string) error {
	// Crear mensaje de actualización de ruta
	routeUpdate := map[string]interface{}{
		"type":        MsgTypeRouteUpdate,
		"destination": dest,
		"route":       route,
		"timestamp":   time.Now().Unix(),
	}

	// Serializar y publicar
	routeUpdateBytes, err := json.Marshal(routeUpdate)
	if err != nil {
		return fmt.Errorf("error al serializar actualización de ruta: %v", err)
	}

	// Publicar en el topic de control
	err = controlTopic.Publish(context.Background(), routeUpdateBytes)
	if err != nil {
		return fmt.Errorf("error al publicar actualización de ruta: %v", err)
	}

	log.Printf("Actualización de ruta publicada para destino %s: %v", dest, route)
	return nil
}

// Obtener una ruta para un destino
func getRouteForDestination(dest string) ([]string, error) {
	knownRoutesMutex.RLock()
	defer knownRoutesMutex.RUnlock()

	route, exists := knownRoutes[dest]
	if !exists {
		return nil, fmt.Errorf("no hay ruta conocida para el destino %s", dest)
	}

	return route, nil
}

// Obtener nodos disponibles para enrutamiento
func getAvailableNodes() []string {
	knownNodesMutex.RLock()
	defer knownNodesMutex.RUnlock()

	// Excluir este nodo
	availableNodes := make([]string, 0, len(knownNodes)-1)
	for id := range knownNodes {
		if id != nodeID {
			availableNodes = append(availableNodes, id)
		}
	}

	return availableNodes
}

// Obtener la clave pública de un nodo
func getNodePublicKey(id string) (*rsa.PublicKey, error) {
	knownNodesMutex.RLock()
	defer knownNodesMutex.RUnlock()

	publicKey, exists := knownNodes[id]
	if !exists {
		return nil, fmt.Errorf("no hay clave pública conocida para el nodo %s", id)
	}

	return publicKey, nil
}
