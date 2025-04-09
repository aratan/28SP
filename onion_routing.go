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
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// Estructura para representar un nodo en la red de enrutamiento cebolla
type OnionNode struct {
	ID        string         // ID del nodo (PeerID)
	PublicKey *rsa.PublicKey // Clave pública del nodo
}

// Estructura para representar una capa de enrutamiento cebolla
type OnionLayer struct {
	NextHop       string `json:"nextHop"`       // ID del siguiente nodo
	EncryptedData []byte `json:"encryptedData"` // Datos cifrados para el siguiente nodo
}

// Estructura para representar un mensaje de enrutamiento cebolla
type OnionMessage struct {
	Type        string     `json:"type"`        // Tipo de mensaje: "data" o "route"
	CurrentHop  string     `json:"currentHop"`  // ID del nodo actual
	NextHop     string     `json:"nextHop"`     // ID del siguiente nodo
	FinalDest   string     `json:"finalDest"`   // ID del destino final
	Layer       OnionLayer `json:"layer"`       // Capa actual del mensaje
	OriginalMsg []byte     `json:"originalMsg"` // Mensaje original (solo presente en el destino final)
}

// Variables globales para el enrutamiento cebolla
var (
	// Mapa de nodos conocidos (ID -> OnionNode)
	knownNodes      = make(map[string]OnionNode)
	knownNodesMutex sync.RWMutex

	// Clave privada de este nodo
	nodePrivateKey *rsa.PrivateKey

	// ID de este nodo
	nodeID string

	// Canal para mensajes de enrutamiento cebolla
	onionTopic *pubsub.Topic
	onionSub   *pubsub.Subscription
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
	var err error

	// Crear un nuevo topic para mensajes de enrutamiento cebolla
	onionTopic, err = ps.Join("onion-routing")
	if err != nil {
		return fmt.Errorf("error al unirse al topic de enrutamiento cebolla: %v", err)
	}

	// Suscribirse al topic
	onionSub, err = onionTopic.Subscribe()
	if err != nil {
		return fmt.Errorf("error al suscribirse al topic de enrutamiento cebolla: %v", err)
	}

	// Iniciar goroutine para procesar mensajes
	go handleOnionMessages()

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
	onionTopic.Publish(ctx, announcementBytes)

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

// Manejar mensajes de enrutamiento cebolla
func handleOnionMessages() {
	for {
		msg, err := onionSub.Next(ctx)
		if err != nil {
			log.Printf("Error al recibir mensaje de enrutamiento cebolla: %v", err)
			continue
		}

		// Ignorar mensajes propios
		if msg.ReceivedFrom == host.ID() {
			continue
		}

		// Procesar el mensaje
		go processOnionMessage(msg.Data)
	}
}

// Procesar un mensaje de enrutamiento cebolla
func processOnionMessage(data []byte) {
	// Intentar decodificar como anuncio de nodo
	var announcement map[string]interface{}
	if err := json.Unmarshal(data, &announcement); err == nil {
		if announcement["type"] == "node_announcement" {
			processNodeAnnouncement(announcement)
			return
		}
	}

	// Intentar decodificar como mensaje de enrutamiento cebolla
	var onionMsg OnionMessage
	if err := json.Unmarshal(data, &onionMsg); err != nil {
		log.Printf("Error al decodificar mensaje de enrutamiento cebolla: %v", err)
		return
	}

	// Comprobar si este nodo es el destinatario actual
	if onionMsg.NextHop != nodeID {
		// Este mensaje no es para nosotros, ignorarlo
		return
	}

	// Procesar el mensaje según su tipo
	switch onionMsg.Type {
	case "data":
		processDataMessage(onionMsg)
	case "route":
		processRouteMessage(onionMsg)
	default:
		log.Printf("Tipo de mensaje desconocido: %s", onionMsg.Type)
	}
}

// Procesar un anuncio de nodo
func processNodeAnnouncement(announcement map[string]interface{}) {
	nodeID, ok := announcement["nodeID"].(string)
	if !ok {
		log.Println("Anuncio de nodo sin ID")
		return
	}

	publicKeyStr, ok := announcement["publicKey"].(string)
	if !ok {
		log.Printf("Anuncio de nodo %s sin clave pública", nodeID)
		return
	}

	publicKey, err := stringToPublicKey(publicKeyStr)
	if err != nil {
		log.Printf("Error al procesar clave pública del nodo %s: %v", nodeID, err)
		return
	}

	// Registrar el nodo
	knownNodesMutex.Lock()
	knownNodes[nodeID] = OnionNode{
		ID:        nodeID,
		PublicKey: publicKey,
	}
	knownNodesMutex.Unlock()

	log.Printf("Nodo registrado: %s", nodeID)
}

// Procesar un mensaje de datos
func processDataMessage(msg OnionMessage) {
	// Descifrar la capa actual
	decryptedData, err := decryptWithPrivateKey(msg.Layer.EncryptedData, nodePrivateKey)
	if err != nil {
		log.Printf("Error al descifrar capa de mensaje: %v", err)
		return
	}

	// Comprobar si somos el destino final
	if msg.FinalDest == nodeID {
		// Somos el destino final, procesar el mensaje original
		var originalMsg Message
		if err := json.Unmarshal(decryptedData, &originalMsg); err != nil {
			log.Printf("Error al decodificar mensaje original: %v", err)
			return
		}

		// Procesar el mensaje como un mensaje normal
		processP2PMessage(originalMsg)
		return
	}

	// No somos el destino final, decodificar la siguiente capa
	var nextLayer OnionLayer
	if err := json.Unmarshal(decryptedData, &nextLayer); err != nil {
		log.Printf("Error al decodificar siguiente capa: %v", err)
		return
	}

	// Crear mensaje para el siguiente salto
	nextMsg := OnionMessage{
		Type:       "data",
		CurrentHop: nodeID,
		NextHop:    nextLayer.NextHop,
		FinalDest:  msg.FinalDest,
		Layer:      nextLayer,
	}

	// Reenviar al siguiente nodo
	forwardOnionMessage(nextMsg)
}

// Procesar un mensaje de ruta
func processRouteMessage(msg OnionMessage) {
	// Los mensajes de ruta son para establecer rutas, no implementados aún
	log.Println("Mensaje de ruta recibido (no implementado)")
}

// Reenviar un mensaje de enrutamiento cebolla
func forwardOnionMessage(msg OnionMessage) {
	// Serializar el mensaje
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error al serializar mensaje para reenvío: %v", err)
		return
	}

	// Publicar en el topic de enrutamiento cebolla
	if err := onionTopic.Publish(ctx, msgBytes); err != nil {
		log.Printf("Error al reenviar mensaje: %v", err)
		return
	}

	log.Printf("Mensaje reenviado al nodo %s", msg.NextHop)
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

// Crear un mensaje con enrutamiento cebolla
func createOnionRoutedMessage(msg Message, route []string) error {
	if len(route) < 1 {
		return fmt.Errorf("la ruta debe tener al menos un nodo")
	}

	// Comprobar que conocemos todos los nodos de la ruta
	knownNodesMutex.RLock()
	defer knownNodesMutex.RUnlock()

	for _, nodeID := range route {
		if _, exists := knownNodes[nodeID]; !exists {
			return fmt.Errorf("nodo desconocido en la ruta: %s", nodeID)
		}
	}

	// Serializar el mensaje original
	originalMsgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje original: %v", err)
	}

	// Construir las capas de enrutamiento cebolla (de adentro hacia afuera)
	// La capa más interna contiene el mensaje original
	var currentData = originalMsgBytes
	var currentLayer OnionLayer

	// Construir las capas en orden inverso (del destino final hacia el primer salto)
	for i := len(route) - 1; i >= 0; i-- {
		nodeID := route[i]
		node := knownNodes[nodeID]

		if i == len(route)-1 {
			// Último nodo (destino final): cifrar el mensaje original
			encryptedData, err := encryptWithPublicKey(currentData, node.PublicKey)
			if err != nil {
				return fmt.Errorf("error al cifrar para el nodo %s: %v", nodeID, err)
			}

			currentLayer = OnionLayer{
				NextHop:       nodeID,
				EncryptedData: encryptedData,
			}
		} else {
			// Nodo intermedio: cifrar la capa anterior
			// Primero serializar la capa anterior
			layerBytes, err := json.Marshal(currentLayer)
			if err != nil {
				return fmt.Errorf("error al serializar capa: %v", err)
			}

			// Cifrar para este nodo
			encryptedData, err := encryptWithPublicKey(layerBytes, node.PublicKey)
			if err != nil {
				return fmt.Errorf("error al cifrar para el nodo %s: %v", nodeID, err)
			}

			// Crear nueva capa
			currentLayer = OnionLayer{
				NextHop:       nodeID,
				EncryptedData: encryptedData,
			}
		}
	}

	// Crear el mensaje de enrutamiento cebolla para el primer nodo
	onionMsg := OnionMessage{
		Type:       "data",
		CurrentHop: nodeID,              // Este nodo
		NextHop:    route[0],            // Primer nodo de la ruta
		FinalDest:  route[len(route)-1], // Último nodo de la ruta
		Layer:      currentLayer,
	}

	// Enviar el mensaje
	return sendOnionMessage(onionMsg)
}

// Enviar un mensaje de enrutamiento cebolla
func sendOnionMessage(msg OnionMessage) error {
	// Serializar el mensaje
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje: %v", err)
	}

	// Publicar en el topic de enrutamiento cebolla
	if err := onionTopic.Publish(ctx, msgBytes); err != nil {
		return fmt.Errorf("error al publicar mensaje: %v", err)
	}

	log.Printf("Mensaje enviado al nodo %s", msg.NextHop)
	return nil
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

// Publicar un mensaje a la red P2P con enrutamiento cebolla
func publishToP2PWithOnion(msg Message) {
	// Aplicar opciones de seguridad al mensaje
	SecureMessageFix(&msg, securityConfig)

	// Seleccionar una ruta aleatoria
	route, err := selectRandomRoute(securityConfig.MinHops, securityConfig.MaxHops)
	if err != nil {
		log.Printf("Error al seleccionar ruta: %v. Usando publicación directa.", err)
		// Fallback a publicación directa
		publishToP2P(msg)
		return
	}

	// Crear y enviar mensaje con enrutamiento cebolla
	if err := createOnionRoutedMessage(msg, route); err != nil {
		log.Printf("Error al crear mensaje con enrutamiento cebolla: %v. Usando publicación directa.", err)
		// Fallback a publicación directa
		publishToP2P(msg)
		return
	}

	log.Printf("Mensaje publicado con enrutamiento cebolla a través de %d nodos", len(route))
}
