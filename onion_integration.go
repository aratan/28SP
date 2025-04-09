package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"chatipfs/onion"
)

// Variables para la integración del enrutamiento cebolla
var (
	// Deshabilitar el enrutamiento de cebolla simulado
	disableRoutingHops = false
)

// Inicializar el sistema de enrutamiento cebolla
func initOnionRouting(ctx context.Context) error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")

	// Inicializar el sistema de enrutamiento cebolla real
	if err := onion.InitOnionRouting(ctx, ps); err != nil {
		return err
	}

	// Actualizar la variable global
	disableRoutingHops = onion.DisableRoutingHops

	return nil
}

// Iniciar la escucha de mensajes de enrutamiento cebolla
func startOnionListener() error {
	log.Println("Iniciando escucha de mensajes de enrutamiento cebolla real...")

	// La escucha ya se inicia en onion.InitOnionRouting
	return nil
}

// Procesar un mensaje recibido
func processReceivedMessage(data []byte) {
	// Intentar decodificar como mensaje de enrutamiento cebolla
	var onionMsg map[string]interface{}
	if err := json.Unmarshal(data, &onionMsg); err == nil {
		msgType, ok := onionMsg["type"].(string)
		if ok && msgType == "onion" {
			// Es un mensaje de enrutamiento cebolla
			currentHop, ok := onionMsg["currentHop"].(string)
			if ok && currentHop == onion.NodeID {
				// Este mensaje es para este nodo
				if err := onion.ProcessOnionMessage(data); err != nil {
					log.Printf("Error al procesar mensaje de enrutamiento cebolla: %v", err)
				}
				return
			}
		}
	}

	// Intentar decodificar como mensaje de control
	var controlMsg map[string]interface{}
	if err := json.Unmarshal(data, &controlMsg); err == nil {
		msgType, ok := controlMsg["type"].(string)
		if ok {
			switch msgType {
			case onion.MsgTypeNodeAnnouncement, onion.MsgTypeKeyExchange, onion.MsgTypeRouteUpdate, onion.MsgTypeNetworkStatus:
				// Es un mensaje de control
				onion.ProcessControlMessage(data)
				return
			}
		}
	}

	// Si no es un mensaje de enrutamiento cebolla ni de control, usar el deserializador seguro tradicional
	msg, err := SecureDeserializeMessageFix(data, p2pKeys)
	if err != nil {
		log.Printf("Error al deserializar mensaje: %v", err)
		return
	}

	// Procesar como mensaje normal
	processP2PMessage(msg)
}

// Publicar un mensaje usando enrutamiento cebolla real
func publishWithRealOnionRouting(msg Message) error {
	return onion.PublishWithRealOnionRouting(p2pTopic, msg)
}

// Publicar usando el método tradicional (simulación de enrutamiento cebolla)
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
