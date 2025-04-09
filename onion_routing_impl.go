package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"
)

// Implementación mejorada de publishToP2P que usa enrutamiento cebolla real
func publishToP2P(msg Message) {
	// Asegurarse de que el mensaje tenga un ID
	if msg.ID == "" {
		msg.ID = generateMessageID()
	}

	log.Printf("Publicando mensaje ID: %s a P2P. Destino: %s", msg.ID, msg.To)

	// Asegurarse de que el mensaje tenga información del remitente
	if msg.From.Username == "" {
		config, _ := readConfig()
		if config != nil && len(config.Users) > 0 {
			msg.From.Username = config.Users[0].Username
		} else {
			msg.From.Username = "anonymous"
		}
	}

	log.Printf("Remitente del mensaje: %s", msg.From.Username)

	// Aplicar opciones de seguridad al mensaje
	SecureMessageFix(&msg, securityConfig)

	log.Printf("Mensaje preparado con seguridad. Encrypted: %v, AnonymousSender: %v",
		msg.Encrypted, msg.AnonymousSender)

	// Verificar si debemos usar enrutamiento cebolla real
	if securityConfig.OnionRouting && !disableRoutingHops {
		// Usar el sistema de enrutamiento cebolla real
		log.Printf("Usando enrutamiento cebolla real para el mensaje ID: %s", msg.ID)
		if err := publishWithRealOnionRouting(msg); err != nil {
			log.Printf(Yellow+"Error en enrutamiento cebolla real: %v. Usando método tradicional."+Reset, err)
			// Fallback al método tradicional
			publishWithTraditionalMethod(msg)
		} else {
			log.Printf(Green+"Mensaje publicado exitosamente con enrutamiento cebolla real. ID: %s"+Reset, msg.ID)
		}
	} else {
		// Usar el método tradicional
		publishWithTraditionalMethod(msg)
	}
}

// Publicar usando el método tradicional (simulación de enrutamiento cebolla)
func publishWithTraditionalMethod(msg Message) {
	// Serializar el mensaje
	serializedMsg, err := SecureSerializeMessageFix(msg, p2pKeys)
	if err != nil {
		log.Printf(Red+"Failed to serialize message: %v"+Reset, err)
		return
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
		log.Printf(Red+"Failed to publish message after retries: %v"+Reset, err)
		return
	}

	log.Printf(Green+"Mensaje publicado exitosamente con método tradicional. ID: %s"+Reset, msg.ID)
}

// Publicar usando enrutamiento cebolla real
func publishWithRealOnionRouting(msg Message) error {
	// Marcar el mensaje como enrutado por cebolla
	msg.OnionRouted = true
	
	// Establecer el nodo de origen
	msg.OriginNode = nodeID
	
	// Seleccionar una ruta aleatoria
	route, err := selectRandomRoute(securityConfig.MinHops, securityConfig.MaxHops)
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
	
	// Preparar las capas cifradas
	msg.EncryptedLayers = make([][]byte, len(route))
	
	// Cifrar el mensaje para cada nodo en la ruta (de adentro hacia afuera)
	currentData := originalMsgBytes
	for i := len(route) - 1; i >= 0; i-- {
		// Obtener la clave pública del nodo
		knownNodesMutex.RLock()
		node, exists := knownNodes[route[i]]
		knownNodesMutex.RUnlock()
		
		if !exists {
			return fmt.Errorf("nodo desconocido en la ruta: %s", route[i])
		}
		
		// Cifrar la capa para este nodo
		encryptedData, err := encryptWithPublicKey(currentData, node.PublicKey)
		if err != nil {
			return fmt.Errorf("error al cifrar para el nodo %s: %v", route[i], err)
		}
		
		// Guardar la capa cifrada
		msg.EncryptedLayers[i] = encryptedData
		
		// Preparar los datos para la siguiente capa
		if i > 0 {
			// Crear un mensaje intermedio para el siguiente nodo
			intermediateMsg := Message{
				ID:           generateMessageID(),
				OnionRouted:  true,
				OriginNode:   nodeID,
				CurrentLayer: i - 1,
				RoutingHops:  route[i-1:],
				OnionData:    encryptedData,
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
		ID:           generateMessageID(),
		OnionRouted:  true,
		OriginNode:   nodeID,
		CurrentLayer: 0,
		RoutingHops:  route,
		OnionData:    msg.EncryptedLayers[0],
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
	
	return nil
}

// Procesar un mensaje de enrutamiento cebolla
func processOnionRoutedMessage(msg Message) {
	// Verificar si este mensaje usa enrutamiento cebolla
	if !msg.OnionRouted {
		// No es un mensaje de enrutamiento cebolla, procesarlo normalmente
		processP2PMessage(msg)
		return
	}
	
	// Verificar si hay datos de cebolla
	if len(msg.OnionData) == 0 {
		log.Printf("Mensaje de enrutamiento cebolla sin datos: %s", msg.ID)
		return
	}
	
	// Verificar si somos el destino final
	if len(msg.RoutingHops) == 0 {
		// Somos el destino final, descifrar y procesar el mensaje original
		decryptedData, err := decryptWithPrivateKey(msg.OnionData, nodePrivateKey)
		if err != nil {
			log.Printf("Error al descifrar mensaje final: %v", err)
			return
		}
		
		// Deserializar el mensaje original
		var originalMsg Message
		if err := json.Unmarshal(decryptedData, &originalMsg); err != nil {
			log.Printf("Error al deserializar mensaje original: %v", err)
			return
		}
		
		// Procesar el mensaje original
		processP2PMessage(originalMsg)
		return
	}
	
	// No somos el destino final, verificar si somos el siguiente salto
	nextHop := msg.RoutingHops[0]
	if nextHop != nodeID {
		// No somos el siguiente salto, ignorar el mensaje
		log.Printf("Mensaje de enrutamiento cebolla para otro nodo: %s", nextHop)
		return
	}
	
	// Somos el siguiente salto, descifrar nuestra capa
	decryptedData, err := decryptWithPrivateKey(msg.OnionData, nodePrivateKey)
	if err != nil {
		log.Printf("Error al descifrar capa de mensaje: %v", err)
		return
	}
	
	// Deserializar el mensaje para el siguiente salto
	var nextMsg Message
	if err := json.Unmarshal(decryptedData, &nextMsg); err != nil {
		log.Printf("Error al deserializar mensaje para siguiente salto: %v", err)
		return
	}
	
	// Actualizar el mensaje con la información del siguiente salto
	nextMsg.RoutingHops = msg.RoutingHops[1:] // Quitar nuestro ID de la ruta
	
	// Reenviar el mensaje al siguiente salto
	forwardOnionMessage(nextMsg)
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
	
	log.Printf("Mensaje reenviado al siguiente salto")
}
