package main

import (
	"context"
	"log"
)

// Función para inicializar el enrutamiento cebolla real
func initRealOnionRouting(ctx context.Context) {
	log.Println("Inicializando enrutamiento cebolla real...")

	// Inicializar el sistema de enrutamiento cebolla
	if err := initOnionRouting(ctx); err != nil {
		log.Printf("Error al inicializar enrutamiento cebolla real: %v", err)
		log.Println("Usando enrutamiento cebolla simulado como fallback")
		return
	}

	log.Println("Enrutamiento cebolla real inicializado correctamente")
}

// Función para procesar mensajes recibidos
func processReceivedMessage(data []byte) {
	// Intentar decodificar como mensaje de control
	var controlMsg map[string]interface{}
	if err := json.Unmarshal(data, &controlMsg); err == nil {
		msgType, ok := controlMsg["type"].(string)
		if ok {
			switch msgType {
			case MsgTypeNodeAnnouncement:
				processNodeAnnouncement(controlMsg)
				return
			case MsgTypeKeyExchange:
				processKeyExchange(controlMsg)
				return
			case MsgTypeRouteUpdate:
				processRouteUpdate(controlMsg)
				return
			case MsgTypeNetworkStatus:
				processNetworkStatus(controlMsg)
				return
			case "onion":
				// Es un mensaje de enrutamiento cebolla
				if err := processOnionMessage(data); err != nil {
					log.Printf("Error al procesar mensaje de enrutamiento cebolla: %v", err)
				}
				return
			}
		}
	}

	// Si no es un mensaje de control ni de enrutamiento cebolla, usar el deserializador seguro tradicional
	msg, err := SecureDeserializeMessageFix(data, p2pKeys)
	if err != nil {
		log.Printf("Error al deserializar mensaje: %v", err)
		return
	}

	// Procesar como mensaje normal
	processP2PMessage(msg)
}
