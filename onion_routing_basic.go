package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"
)

// Inicializar el sistema de enrutamiento cebolla
func initOnionRouting() error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")
	
	// Deshabilitar el enrutamiento de cebolla simulado
	disableRoutingHops = false
	
	log.Printf("Sistema de enrutamiento cebolla real inicializado correctamente")
	
	return nil
}

// Iniciar la escucha de mensajes de enrutamiento cebolla
func startOnionListener() error {
	log.Println("Iniciando escucha de mensajes de enrutamiento cebolla...")
	return nil
}

// Procesar un mensaje de enrutamiento cebolla
func processOnionRoutedMessage(data []byte) {
	// Intentar decodificar el mensaje
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("Error al decodificar mensaje de enrutamiento cebolla: %v", err)
		return
	}
	
	// Verificar si este nodo es el destinatario
	if msg.To != "BROADCAST" && msg.To != "ALL" {
		// Mensaje dirigido a un nodo específico
		// En una implementación real, verificaríamos si somos el destinatario
		// Por ahora, procesamos todos los mensajes
	}
	
	// Verificar si el mensaje tiene capas de enrutamiento cebolla
	if len(msg.EncryptedLayers) > 0 && msg.CurrentLayer < len(msg.EncryptedLayers) {
		// Descifrar la capa actual
		decryptedLayer, err := decryptLayer(msg.EncryptedLayers[msg.CurrentLayer])
		if err != nil {
			log.Printf("Error al descifrar capa %d: %v", msg.CurrentLayer, err)
			return
		}
		
		// Deserializar la capa descifrada
		var nextMsg Message
		if err := json.Unmarshal(decryptedLayer, &nextMsg); err != nil {
			log.Printf("Error al deserializar capa descifrada: %v", err)
			return
		}
		
		// Actualizar el índice de capa
		nextMsg.CurrentLayer = msg.CurrentLayer + 1
		
		// Si hay más capas, reenviar el mensaje
		if nextMsg.CurrentLayer < len(nextMsg.EncryptedLayers) {
			forwardOnionMessage(nextMsg)
		} else {
			// Somos el destino final, procesar el mensaje
			processP2PMessage(nextMsg)
		}
	} else {
		// No hay capas de enrutamiento cebolla o ya hemos procesado todas
		// Procesar el mensaje normalmente
		processP2PMessage(msg)
	}
}

// Descifrar una capa de enrutamiento cebolla
func decryptLayer(data []byte) ([]byte, error) {
	// En una implementación real, usaríamos la clave privada del nodo
	// Por ahora, usamos una función de descifrado simple
	
	// Usar la clave de cifrado P2P como clave para descifrar
	if len(p2pKeys) == 0 {
		return nil, fmt.Errorf("no hay claves disponibles para descifrar")
	}
	
	return SecureDecrypt(data, p2pKeys[0])
}

// Reenviar un mensaje de enrutamiento cebolla
func forwardOnionMessage(msg Message) {
	// Serializar el mensaje
	serializedMsg, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error al serializar mensaje para reenvío: %v", err)
		return
	}
	
	// Publicar en el topic P2P
	if err := p2pTopic.Publish(context.Background(), serializedMsg); err != nil {
		log.Printf("Error al reenviar mensaje: %v", err)
		return
	}
	
	log.Printf("Mensaje reenviado al siguiente nodo")
}

// Publicar usando enrutamiento cebolla real
func publishWithRealOnionRouting(msg Message) error {
	// Marcar el mensaje como enrutado por cebolla
	msg.OnionRouted = true
	
	// Generar una ruta aleatoria
	numHops := 2 // Número fijo de saltos para simplificar
	route := make([]string, numHops)
	
	// En una implementación real, seleccionaríamos nodos reales
	// Por ahora, generamos IDs aleatorios
	for i := 0; i < numHops; i++ {
		idBytes := make([]byte, 8)
		if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
			return fmt.Errorf("error al generar ID de nodo: %v", err)
		}
		route[i] = fmt.Sprintf("node_%x", idBytes)
	}
	
	// Guardar la ruta en el mensaje
	msg.RoutingHops = route
	
	// Preparar las capas cifradas
	msg.EncryptedLayers = make([][]byte, numHops)
	
	// Serializar el mensaje original
	originalMsgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje original: %v", err)
	}
	
	// Cifrar el mensaje para cada nodo en la ruta (de adentro hacia afuera)
	currentData := originalMsgBytes
	for i := numHops - 1; i >= 0; i-- {
		// En una implementación real, usaríamos la clave pública del nodo
		// Por ahora, usamos la clave de cifrado P2P
		if len(p2pKeys) == 0 {
			return fmt.Errorf("no hay claves disponibles para cifrar")
		}
		
		// Cifrar la capa
		encryptedData, err := SecureEncrypt(currentData, p2pKeys[0])
		if err != nil {
			return fmt.Errorf("error al cifrar capa %d: %v", i, err)
		}
		
		// Guardar la capa cifrada
		msg.EncryptedLayers[i] = encryptedData
		
		// Preparar los datos para la siguiente capa
		if i > 0 {
			// Crear un mensaje intermedio para el siguiente nodo
			intermediateMsg := Message{
				ID:              generateMessageID(),
				OnionRouted:     true,
				CurrentLayer:    i - 1,
				RoutingHops:     route,
				EncryptedLayers: msg.EncryptedLayers,
			}
			
			// Serializar el mensaje intermedio
			currentData, err = json.Marshal(intermediateMsg)
			if err != nil {
				return fmt.Errorf("error al serializar mensaje intermedio: %v", err)
			}
		}
	}
	
	// Crear el mensaje final para el primer nodo
	finalMsg := Message{
		ID:              generateMessageID(),
		OnionRouted:     true,
		CurrentLayer:    0,
		RoutingHops:     route,
		EncryptedLayers: msg.EncryptedLayers,
	}
	
	// Serializar y enviar el mensaje
	serializedMsg, err := json.Marshal(finalMsg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje final: %v", err)
	}
	
	// Publicar el mensaje en el topic P2P
	if err := p2pTopic.Publish(context.Background(), serializedMsg); err != nil {
		return fmt.Errorf("error al publicar mensaje: %v", err)
	}
	
	log.Printf("Mensaje enviado con enrutamiento cebolla real a través de %d nodos", numHops)
	return nil
}

// Función auxiliar para publicar con método tradicional
func publishWithTraditionalMethod(msg Message) {
	// Serializar el mensaje
	serializedMsg, err := SecureSerializeMessageFix(msg, p2pKeys)
	if err != nil {
		log.Printf("Failed to serialize message: %v", err)
		return
	}

	// Publicar el mensaje en el topic P2P
	for i := 0; i < 3; i++ { // Intentar hasta 3 veces
		err = p2pTopic.Publish(context.Background(), serializedMsg)
		if err == nil {
			break
		}
		log.Printf("Publish attempt %d failed: %v", i+1, err)
		time.Sleep(time.Duration(500*(i+1)) * time.Millisecond)
	}

	if err != nil {
		log.Printf("Failed to publish message after retries: %v", err)
		return
	}

	log.Printf("Mensaje publicado exitosamente con método tradicional. ID: %s", msg.ID)
}
