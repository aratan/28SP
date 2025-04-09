package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"
)

// Variables globales para el enrutamiento cebolla
var (
	// Mapa de nodos conocidos (ID -> clave)
	knownNodes      = make(map[string][]byte)
	knownNodesMutex sync.RWMutex

	// ID de este nodo
	nodeID string

	// Clave de este nodo
	nodeKey []byte
)

// Inicializar el sistema de enrutamiento cebolla
func initOnionRouting() error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")

	// Generar un ID aleatorio para este nodo
	idBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return fmt.Errorf("error al generar ID de nodo: %v", err)
	}
	nodeID = fmt.Sprintf("%x", idBytes)

	// Generar una clave para este nodo
	nodeKey = make([]byte, 32) // Clave AES-256
	if _, err := io.ReadFull(rand.Reader, nodeKey); err != nil {
		return fmt.Errorf("error al generar clave de nodo: %v", err)
	}

	// Registrar este nodo
	knownNodesMutex.Lock()
	knownNodes[nodeID] = nodeKey
	knownNodesMutex.Unlock()

	log.Printf("Nodo inicializado con ID: %s", nodeID)

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
		"publicKey": base64.StdEncoding.EncodeToString(nodeKey),
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

// Cifrar datos con AES-GCM
func encryptLayer(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
func decryptLayer(data []byte, key []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("datos demasiado cortos para contener un nonce")
	}

	// Extraer el nonce
	nonce := data[:12]
	ciphertext := data[12:]

	// Crear el cifrador AES
	block, err := aes.NewCipher(key)
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

// Procesar un mensaje de anuncio de nodo
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

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		log.Printf("Error al decodificar clave pública del nodo %s: %v", nodeID, err)
		return
	}

	// Registrar el nodo
	knownNodesMutex.Lock()
	knownNodes[nodeID] = publicKey
	knownNodesMutex.Unlock()

	log.Printf("Nodo registrado: %s", nodeID)
}

// Publicar usando enrutamiento cebolla real
func publishWithRealOnionRouting(msg Message) error {
	// Marcar el mensaje como enrutado por cebolla
	msg.OnionRouted = true

	// Establecer el nodo de origen
	msg.OriginNode = nodeID

	// Seleccionar una ruta aleatoria
	route, err := selectRandomRoute(2, 3) // Mínimo 2, máximo 3 saltos
	if err != nil {
		return fmt.Errorf("error al seleccionar ruta: %v", err)
	}

	// Guardar la ruta en el mensaje
	msg.RoutingHops = route

	// Serializar el mensaje original
	originalMsgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje original: %v", err)
	}

	// Cifrar el mensaje para cada nodo en la ruta (de adentro hacia afuera)
	currentData := originalMsgBytes
	for i := len(route) - 1; i >= 0; i-- {
		// Obtener la clave del nodo
		knownNodesMutex.RLock()
		nodeKey, exists := knownNodes[route[i]]
		knownNodesMutex.RUnlock()

		if !exists {
			return fmt.Errorf("nodo desconocido en la ruta: %s", route[i])
		}

		// Crear un mensaje intermedio para el siguiente nodo
		var nextHop string
		if i > 0 {
			nextHop = route[i-1]
		} else {
			nextHop = "final"
		}

		intermediateMsg := map[string]interface{}{
			"type":       "onion_layer",
			"nextHop":    nextHop,
			"data":       currentData,
			"timestamp":  time.Now().Unix(),
			"layerIndex": i,
		}

		// Serializar el mensaje intermedio
		intermediateBytes, err := json.Marshal(intermediateMsg)
		if err != nil {
			return fmt.Errorf("error al serializar mensaje intermedio: %v", err)
		}

		// Cifrar la capa para este nodo
		encryptedData, err := encryptLayer(intermediateBytes, nodeKey)
		if err != nil {
			return fmt.Errorf("error al cifrar para el nodo %s: %v", route[i], err)
		}

		// Actualizar los datos para la siguiente capa
		currentData = encryptedData
	}

	// Crear el mensaje final para el primer nodo
	finalMsg := map[string]interface{}{
		"type":      "onion_message",
		"firstHop":  route[0],
		"data":      currentData,
		"timestamp": time.Now().Unix(),
		"sender":    nodeID,
	}

	// Serializar y enviar el mensaje
	serializedMsg, err := json.Marshal(finalMsg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje final: %v", err)
	}

	// Publicar el mensaje en el topic P2P
	for i := 0; i < 3; i++ { // Intentar hasta 3 veces
		err = p2pTopic.Publish(context.Background(), serializedMsg)
		if err == nil {
			break
		}
		log.Printf(Yellow+"Publish attempt %d failed: %v"+Reset, i+1, err)
		time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
	}

	if err != nil {
		return fmt.Errorf("error al publicar mensaje después de reintentos: %v", err)
	}

	log.Printf("Mensaje enviado con enrutamiento cebolla real a través de %d nodos", len(route))
	return nil
}

// Procesar un mensaje de enrutamiento cebolla
func processOnionRoutedMessage(data []byte) {
	// Intentar decodificar como anuncio de nodo
	var announcement map[string]interface{}
	if err := json.Unmarshal(data, &announcement); err == nil {
		if announcement["type"] == "node_announcement" {
			processNodeAnnouncement(announcement)
			return
		}
	}

	// Intentar decodificar como mensaje de enrutamiento cebolla
	var onionMsg map[string]interface{}
	if err := json.Unmarshal(data, &onionMsg); err != nil {
		log.Printf("Error al decodificar mensaje de enrutamiento cebolla: %v", err)
		return
	}

	// Procesar según el tipo de mensaje
	msgType, _ := onionMsg["type"].(string)
	switch msgType {
	case "onion_message":
		// Mensaje inicial de enrutamiento cebolla
		firstHop, _ := onionMsg["firstHop"].(string)
		if firstHop != nodeID {
			// Este mensaje no es para nosotros, ignorarlo
			return
		}

		// Obtener los datos cifrados
		encryptedData, ok := onionMsg["data"].([]byte)
		if !ok {
			// Intentar convertir desde string base64
			encryptedDataStr, ok := onionMsg["data"].(string)
			if !ok {
				log.Printf("Formato de datos inválido en mensaje de enrutamiento cebolla")
				return
			}
			encryptedData, err := base64.StdEncoding.DecodeString(encryptedDataStr)
			if err != nil {
				log.Printf("Error al decodificar datos cifrados: %v", err)
				return
			}
			processOnionLayer(encryptedData)
		} else {
			processOnionLayer(encryptedData)
		}

	case "onion_layer":
		// Capa intermedia de enrutamiento cebolla
		nextHop, _ := onionMsg["nextHop"].(string)
		if nextHop != nodeID && nextHop != "final" {
			// Este mensaje no es para nosotros, ignorarlo
			return
		}

		// Obtener los datos cifrados
		encryptedData, ok := onionMsg["data"].([]byte)
		if !ok {
			// Intentar convertir desde string base64
			encryptedDataStr, ok := onionMsg["data"].(string)
			if !ok {
				log.Printf("Formato de datos inválido en capa de enrutamiento cebolla")
				return
			}
			encryptedData, err := base64.StdEncoding.DecodeString(encryptedDataStr)
			if err != nil {
				log.Printf("Error al decodificar datos cifrados: %v", err)
				return
			}
			processOnionLayer(encryptedData)
		} else {
			processOnionLayer(encryptedData)
		}
	}
}

// Procesar una capa de enrutamiento cebolla
func processOnionLayer(encryptedData []byte) {
	// Descifrar la capa con nuestra clave
	decryptedData, err := decryptLayer(encryptedData, nodeKey)
	if err != nil {
		log.Printf("Error al descifrar capa de enrutamiento cebolla: %v", err)
		return
	}

	// Decodificar el mensaje intermedio
	var intermediateMsg map[string]interface{}
	if err := json.Unmarshal(decryptedData, &intermediateMsg); err != nil {
		log.Printf("Error al decodificar mensaje intermedio: %v", err)
		return
	}

	// Obtener el siguiente salto
	nextHop, _ := intermediateMsg["nextHop"].(string)

	// Comprobar si somos el destino final
	if nextHop == "final" {
		// Somos el destino final, procesar el mensaje original
		originalData, ok := intermediateMsg["data"].([]byte)
		if !ok {
			// Intentar convertir desde string base64
			originalDataStr, ok := intermediateMsg["data"].(string)
			if !ok {
				log.Printf("Formato de datos inválido en mensaje final")
				return
			}
			originalData, err := base64.StdEncoding.DecodeString(originalDataStr)
			if err != nil {
				log.Printf("Error al decodificar mensaje original: %v", err)
				return
			}

			// Decodificar el mensaje original
			var originalMsg Message
			if err := json.Unmarshal(originalData, &originalMsg); err != nil {
				log.Printf("Error al decodificar mensaje original: %v", err)
				return
			}

			// Procesar el mensaje original
			processP2PMessage(originalMsg)
		} else {
			// Decodificar el mensaje original
			var originalMsg Message
			if err := json.Unmarshal(originalData, &originalMsg); err != nil {
				log.Printf("Error al decodificar mensaje original: %v", err)
				return
			}

			// Procesar el mensaje original
			processP2PMessage(originalMsg)
		}
		return
	}

	// No somos el destino final, reenviar al siguiente nodo
	// Obtener los datos para el siguiente nodo
	nextData, ok := intermediateMsg["data"].([]byte)
	if !ok {
		// Intentar convertir desde string base64
		nextDataStr, ok := intermediateMsg["data"].(string)
		if !ok {
			log.Printf("Formato de datos inválido para siguiente nodo")
			return
		}
		nextData, err := base64.StdEncoding.DecodeString(nextDataStr)
		if err != nil {
			log.Printf("Error al decodificar datos para siguiente nodo: %v", err)
			return
		}
		forwardOnionLayer(nextHop, nextData)
	} else {
		forwardOnionLayer(nextHop, nextData)
	}
}

// Reenviar una capa de enrutamiento cebolla al siguiente nodo
func forwardOnionLayer(nextHop string, data []byte) {
	// Crear mensaje para el siguiente nodo
	forwardMsg := map[string]interface{}{
		"type":      "onion_layer",
		"nextHop":   nextHop,
		"data":      data,
		"timestamp": time.Now().Unix(),
		"relay":     nodeID,
	}

	// Serializar y enviar
	serializedMsg, err := json.Marshal(forwardMsg)
	if err != nil {
		log.Printf("Error al serializar mensaje para reenvío: %v", err)
		return
	}

	// Publicar en el topic P2P
	if err := p2pTopic.Publish(context.Background(), serializedMsg); err != nil {
		log.Printf("Error al reenviar mensaje: %v", err)
		return
	}

	log.Printf("Mensaje reenviado al nodo %s", nextHop)
}
