package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"./onion"
)

// Inicializar el sistema de enrutamiento cebolla real
func initRealOnionRouting(ctx context.Context) error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")

	// Inicializar el sistema de enrutamiento cebolla real
	if err := onion.InitOnionRouting(ctx, PS); err != nil {
		return err
	}

	// Deshabilitar el enrutamiento de cebolla simulado
	DisableRoutingHops = true

	log.Println("Sistema de enrutamiento cebolla real inicializado correctamente")
	return nil
}

// Procesar un mensaje recibido con posible enrutamiento cebolla
func ProcessReceivedMessage(data []byte) (bool, Message) {
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
				return true, Message{} // Mensaje procesado por el sistema de enrutamiento cebolla
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
				return true, Message{} // Mensaje procesado por el sistema de enrutamiento cebolla
			}
		}
	}

	// Si no es un mensaje de enrutamiento cebolla ni de control, usar el deserializador seguro tradicional
	msg, err := SecureDeserializeMessageFix(data, P2PKeys)
	if err != nil {
		log.Printf("Error al deserializar mensaje: %v", err)
		return false, Message{} // Error al procesar el mensaje
	}

	// Mensaje normal
	return false, msg
}

// Publicar un mensaje usando enrutamiento cebolla real
func PublishWithRealOnionRouting(msg Message) error {
	return onion.PublishWithRealOnionRouting(P2PTopic, msg)
}

// Publicar un mensaje usando el método tradicional o el enrutamiento cebolla real
func PublishMessageWithOnionRouting(msg Message) {
	// Asegurarse de que el mensaje tenga un ID
	if msg.ID == "" {
		msg.ID = GenerateMessageID()
	}

	log.Printf("Publicando mensaje ID: %s a P2P. Destino: %s", msg.ID, msg.To)

	// Asegurarse de que el mensaje tenga información del remitente
	if msg.From.Username == "" {
		config, _ := ReadConfig()
		if config != nil && len(config.Users) > 0 {
			msg.From.Username = config.Users[0].Username
		} else {
			msg.From.Username = "anonymous"
		}
	}

	log.Printf("Remitente del mensaje: %s", msg.From.Username)

	// Aplicar opciones de seguridad al mensaje
	SecureMessageFix(&msg, SecurityConfigInstance)

	log.Printf("Mensaje preparado con seguridad. Encrypted: %v, AnonymousSender: %v",
		msg.Encrypted, msg.AnonymousSender)

	// Verificar si debemos usar enrutamiento cebolla real
	if SecurityConfigInstance.OnionRouting && !DisableRoutingHops {
		// Usar el sistema de enrutamiento cebolla real
		log.Printf("Usando enrutamiento cebolla real para el mensaje ID: %s", msg.ID)
		if err := PublishWithRealOnionRouting(msg); err != nil {
			log.Printf("Error en enrutamiento cebolla real: %v. Usando método tradicional.", err)
			// Fallback al método tradicional
			PublishWithTraditionalMethod(msg)
		} else {
			log.Printf("Mensaje publicado exitosamente con enrutamiento cebolla real. ID: %s", msg.ID)
		}
	} else {
		// Usar el método tradicional
		PublishWithTraditionalMethod(msg)
	}
}

// Publicar usando el método tradicional (simulación de enrutamiento cebolla)
func PublishWithTraditionalMethod(msg Message) {
	// Serializar el mensaje
	serializedMsg, err := SecureSerializeMessageFix(msg, P2PKeys)
	if err != nil {
		log.Printf("Failed to serialize message: %v", err)
		return
	}

	// Publicar el mensaje en el topic P2P
	for i := 0; i < 3; i++ { // Intentar hasta 3 veces
		err = P2PTopic.Publish(context.Background(), serializedMsg)
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
