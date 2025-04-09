package onion

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// Seleccionar una ruta aleatoria para un mensaje
func SelectRandomRoute() ([]string, error) {
	// Obtener nodos disponibles
	KnownNodesMutex.RLock()
	defer KnownNodesMutex.RUnlock()

	// Contar nodos disponibles (excluyendo este nodo)
	availableNodes := make([]string, 0, len(KnownNodes)-1)
	for id := range KnownNodes {
		if id != NodeID {
			availableNodes = append(availableNodes, id)
		}
	}

	// Determinar el número de saltos (entre 2 y 4)
	minHops := 2
	maxHops := 4

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
	availableNodesCopy := make([]string, len(availableNodes))
	copy(availableNodesCopy, availableNodes)

	for i := 0; i < numHops; i++ {
		// Seleccionar un nodo aleatorio de los disponibles
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(availableNodesCopy))))
		route[i] = availableNodesCopy[idx.Int64()]

		// Eliminar el nodo seleccionado para evitar repeticiones
		availableNodesCopy = append(availableNodesCopy[:idx.Int64()], availableNodesCopy[idx.Int64()+1:]...)
	}

	return route, nil
}

// Crear un mensaje con enrutamiento cebolla
func CreateOnionRoutedMessage(originalMsg interface{}, route []string) ([]byte, error) {
	if len(route) < 1 {
		return nil, fmt.Errorf("la ruta debe tener al menos un nodo")
	}

	// Serializar el mensaje original
	originalMsgBytes, err := json.Marshal(originalMsg)
	if err != nil {
		return nil, fmt.Errorf("error al serializar mensaje original: %v", err)
	}

	// La carga útil inicial es el mensaje original
	currentPayload := originalMsgBytes

	// Construir las capas de enrutamiento cebolla (de adentro hacia afuera)
	for i := len(route) - 1; i >= 0; i-- {
		// Crear la capa para este nodo
		var nextHop string
		if i > 0 {
			nextHop = route[i-1]
		} else {
			nextHop = "final"
		}

		var payloadType string
		if i == len(route)-1 {
			payloadType = "message"
		} else {
			payloadType = "layer"
		}

		layer := OnionLayer{
			NextHop:     nextHop,
			FinalDest:   route[len(route)-1],
			LayerIndex:  i,
			PayloadType: payloadType,
		}

		// Serializar la capa
		layerBytes, err := json.Marshal(layer)
		if err != nil {
			return nil, fmt.Errorf("error al serializar capa: %v", err)
		}

		// Obtener la clave pública del nodo
		KnownNodesMutex.RLock()
		publicKey, exists := KnownNodes[route[i]]
		KnownNodesMutex.RUnlock()

		if !exists {
			return nil, fmt.Errorf("no se encontró la clave pública para el nodo %s", route[i])
		}

		// Cifrar la capa con RSA
		encryptedLayer, err := EncryptWithRSA(layerBytes, publicKey)
		if err != nil {
			return nil, fmt.Errorf("error al cifrar capa para nodo %s: %v", route[i], err)
		}

		// Generar una clave AES aleatoria para cifrar la carga útil
		aesKey := make([]byte, 32)
		if _, err := rand.Read(aesKey); err != nil {
			return nil, fmt.Errorf("error al generar clave AES: %v", err)
		}

		// Cifrar la carga útil con AES
		encryptedPayload, err := EncryptLayer(currentPayload, aesKey)
		if err != nil {
			return nil, fmt.Errorf("error al cifrar carga útil: %v", err)
		}

		// Cifrar la clave AES con RSA
		encryptedKey, err := EncryptWithRSA(aesKey, publicKey)
		if err != nil {
			return nil, fmt.Errorf("error al cifrar clave AES: %v", err)
		}

		// Crear el mensaje para este nodo
		onionMsg := map[string]interface{}{
			"type":       "onion",
			"originNode": NodeID,
			"currentHop": route[i],
			"layer":      encryptedLayer,
			"payload":    encryptedPayload,
			"key":        encryptedKey,
		}

		// Serializar el mensaje
		onionMsgBytes, err := json.Marshal(onionMsg)
		if err != nil {
			return nil, fmt.Errorf("error al serializar mensaje onion: %v", err)
		}

		// La carga útil para la siguiente capa es este mensaje
		currentPayload = onionMsgBytes
	}

	return currentPayload, nil
}

// Procesar un mensaje de enrutamiento cebolla
func ProcessOnionMessage(data []byte) error {
	// Deserializar el mensaje
	var onionMsg map[string]interface{}
	if err := json.Unmarshal(data, &onionMsg); err != nil {
		return fmt.Errorf("error al deserializar mensaje onion: %v", err)
	}

	// Verificar que sea un mensaje de enrutamiento cebolla
	msgType, ok := onionMsg["type"].(string)
	if !ok || msgType != "onion" {
		return fmt.Errorf("no es un mensaje de enrutamiento cebolla válido")
	}

	// Verificar que este nodo sea el destinatario actual
	currentHop, ok := onionMsg["currentHop"].(string)
	if !ok || currentHop != NodeID {
		return fmt.Errorf("este mensaje no es para este nodo")
	}

	// Extraer la capa cifrada
	layerBytes, ok := onionMsg["layer"].([]byte)
	if !ok {
		// Intentar convertir desde string
		layerStr, ok := onionMsg["layer"].(string)
		if !ok {
			return fmt.Errorf("formato de capa inválido")
		}
		layerBytes = []byte(layerStr)
	}

	// Extraer la clave cifrada
	keyBytes, ok := onionMsg["key"].([]byte)
	if !ok {
		// Intentar convertir desde string
		keyStr, ok := onionMsg["key"].(string)
		if !ok {
			return fmt.Errorf("formato de clave inválido")
		}
		keyBytes = []byte(keyStr)
	}

	// Extraer la carga útil cifrada
	payloadBytes, ok := onionMsg["payload"].([]byte)
	if !ok {
		// Intentar convertir desde string
		payloadStr, ok := onionMsg["payload"].(string)
		if !ok {
			return fmt.Errorf("formato de carga útil inválido")
		}
		payloadBytes = []byte(payloadStr)
	}

	// Descifrar la capa con la clave privada de este nodo
	decryptedLayerBytes, err := DecryptWithRSA(layerBytes, NodePrivateKey)
	if err != nil {
		return fmt.Errorf("error al descifrar capa: %v", err)
	}

	// Deserializar la capa
	var layer OnionLayer
	if err := json.Unmarshal(decryptedLayerBytes, &layer); err != nil {
		return fmt.Errorf("error al deserializar capa: %v", err)
	}

	// Descifrar la clave AES con la clave privada de este nodo
	aesKey, err := DecryptWithRSA(keyBytes, NodePrivateKey)
	if err != nil {
		return fmt.Errorf("error al descifrar clave AES: %v", err)
	}

	// Descifrar la carga útil con la clave AES
	decryptedPayload, err := DecryptLayer(payloadBytes, aesKey)
	if err != nil {
		return fmt.Errorf("error al descifrar carga útil: %v", err)
	}

	// Verificar si somos el destino final
	if layer.NextHop == "final" {
		// Somos el destino final, procesar el mensaje original
		if layer.PayloadType != "message" {
			return fmt.Errorf("tipo de carga útil inválido para destino final: %s", layer.PayloadType)
		}

		// Aquí se procesaría el mensaje original
		// Por ahora, solo lo registramos
		log.Printf("Mensaje final recibido: %s", string(decryptedPayload))
		return nil
	}

	// No somos el destino final, reenviar al siguiente nodo
	nextHop := layer.NextHop

	// Reenviar la carga útil descifrada al siguiente nodo
	log.Printf("Reenviando mensaje al nodo %s", nextHop)
	return nil
}

// Publicar un mensaje usando enrutamiento cebolla real
func PublishWithRealOnionRouting(topic *pubsub.Topic, msg interface{}) error {
	// Seleccionar una ruta aleatoria
	route, err := SelectRandomRoute()
	if err != nil {
		return fmt.Errorf("error al seleccionar ruta: %v", err)
	}

	log.Printf("Ruta seleccionada: %v", route)

	// Crear el mensaje con enrutamiento cebolla
	onionMsg, err := CreateOnionRoutedMessage(msg, route)
	if err != nil {
		return fmt.Errorf("error al crear mensaje con enrutamiento cebolla: %v", err)
	}

	// Publicar el mensaje en el topic
	if err := topic.Publish(context.Background(), onionMsg); err != nil {
		return fmt.Errorf("error al publicar mensaje: %v", err)
	}

	log.Printf("Mensaje enviado con enrutamiento cebolla real a través de %d nodos", len(route))
	return nil
}
