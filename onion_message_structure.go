package main

import (
	"encoding/json"
	"fmt"
)

// Estructura para representar una capa de enrutamiento cebolla
type OnionLayer struct {
	NextHop     string `json:"nextHop"`     // ID del siguiente nodo
	FinalDest   string `json:"finalDest"`   // ID del destino final
	PayloadType string `json:"payloadType"` // Tipo de carga útil: "message" o "layer"
}

// Estructura para representar un mensaje de enrutamiento cebolla
type OnionMessage struct {
	Type           string `json:"type"`           // Tipo de mensaje: "onion"
	OriginNode     string `json:"originNode"`     // ID del nodo de origen
	CurrentHop     string `json:"currentHop"`     // ID del nodo actual
	EncryptedLayer []byte `json:"encryptedLayer"` // Capa cifrada para el nodo actual
	Payload        []byte `json:"payload"`        // Carga útil cifrada (siguiente capa o mensaje final)
}

// Crear un mensaje con enrutamiento cebolla
func createOnionRoutedMessage(originalMsg Message, route []string) ([]byte, error) {
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
			PayloadType: payloadType,
		}

		// Serializar la capa
		layerBytes, err := json.Marshal(layer)
		if err != nil {
			return nil, fmt.Errorf("error al serializar capa: %v", err)
		}

		// Cifrar la capa para este nodo
		encryptedLayer, err := encryptForNode(route[i], layerBytes)
		if err != nil {
			return nil, fmt.Errorf("error al cifrar capa para nodo %s: %v", route[i], err)
		}

		// Crear el mensaje para este nodo
		onionMsg := OnionMessage{
			Type:           "onion",
			OriginNode:     nodeID,
			CurrentHop:     route[i],
			EncryptedLayer: encryptedLayer,
			Payload:        currentPayload,
		}

		// Serializar el mensaje
		onionMsgBytes, err := json.Marshal(onionMsg)
		if err != nil {
			return nil, fmt.Errorf("error al serializar mensaje onion: %v", err)
		}

		// La carga útil para la siguiente capa es este mensaje
		currentPayload = onionMsgBytes

		// Si no es el primer nodo, cifrar la carga útil para el siguiente nodo
		if i > 0 {
			currentPayload, err = encryptForNode(route[i-1], currentPayload)
			if err != nil {
				return nil, fmt.Errorf("error al cifrar carga útil para nodo %s: %v", route[i-1], err)
			}
		}
	}

	// El resultado final es la carga útil para el primer nodo
	return currentPayload, nil
}

// Procesar un mensaje de enrutamiento cebolla
func processOnionMessage(data []byte) error {
	// Deserializar el mensaje
	var onionMsg OnionMessage
	if err := json.Unmarshal(data, &onionMsg); err != nil {
		return fmt.Errorf("error al deserializar mensaje onion: %v", err)
	}

	// Verificar que este nodo sea el destinatario actual
	if onionMsg.CurrentHop != nodeID {
		return fmt.Errorf("este mensaje no es para este nodo")
	}

	// Descifrar la capa con la clave privada de este nodo
	layerBytes, err := decryptWithNodeKey(onionMsg.EncryptedLayer)
	if err != nil {
		return fmt.Errorf("error al descifrar capa: %v", err)
	}

	// Deserializar la capa
	var layer OnionLayer
	if err := json.Unmarshal(layerBytes, &layer); err != nil {
		return fmt.Errorf("error al deserializar capa: %v", err)
	}

	// Verificar si somos el destino final
	if layer.NextHop == "final" {
		// Somos el destino final, procesar el mensaje original
		var originalMsg Message
		if err := json.Unmarshal(onionMsg.Payload, &originalMsg); err != nil {
			return fmt.Errorf("error al deserializar mensaje original: %v", err)
		}

		// Procesar el mensaje original
		processP2PMessage(originalMsg)
		return nil
	}

	// No somos el destino final, reenviar al siguiente nodo
	nextHop := layer.NextHop

	// Descifrar la carga útil para el siguiente nodo
	nextPayload, err := decryptWithNodeKey(onionMsg.Payload)
	if err != nil {
		return fmt.Errorf("error al descifrar carga útil para siguiente nodo: %v", err)
	}

	// Crear el mensaje para el siguiente nodo
	nextMsg := OnionMessage{
		Type:           "onion",
		OriginNode:     onionMsg.OriginNode,
		CurrentHop:     nextHop,
		EncryptedLayer: nil, // Se llenará en el siguiente nodo
		Payload:        nextPayload,
	}

	// Serializar y enviar el mensaje
	nextMsgBytes, err := json.Marshal(nextMsg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje para siguiente nodo: %v", err)
	}

	// Reenviar al siguiente nodo
	return forwardToNode(nextHop, nextMsgBytes)
}
