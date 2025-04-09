package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
	// Importar el paquete onion para enrutamiento cebolla real
)

// Función mejorada para publicar mensajes
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
			log.Printf("Error en enrutamiento cebolla real: %v. Usando método tradicional.", err)
			// Fallback al método tradicional
			publishWithTraditionalMethod(msg)
		} else {
			log.Printf("Mensaje publicado exitosamente con enrutamiento cebolla real. ID: %s", msg.ID)
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

// Función mejorada para manejar mensajes P2P
func handleP2PMessages(ctx context.Context) {
	log.Printf("Iniciando manejador de mensajes P2P...")
	for {
		log.Printf("Esperando mensajes P2P...")
		m, err := p2pSub.Next(ctx)
		if err != nil {
			log.Printf("Failed to get next message: %v", err)
			continue
		}
		// Log the message data size before deserialization
		log.Printf("Received message from %s, data size: %d bytes", m.ReceivedFrom, len(m.Message.Data))

		// Procesar el mensaje recibido
		processReceivedMessage(m.Message.Data)
	}
}

// Función para procesar mensajes P2P normales
func processP2PMessage(msg Message) {
	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	// Log successful deserialization
	log.Printf("Successfully deserialized message from %s", msg.From.Username)

	// Handle binary transfer messages
	if msg.Action == "binary_transfer" {
		log.Printf("Received binary file: %s", msg.FileName)
		// Process the binary data (e.g., save to disk)
		receivedDir := "received_files"
		if err := os.MkdirAll(receivedDir, 0755); err != nil {
			log.Printf("Error creating directory for received files: %v", err)
			return
		}
		outputPath := filepath.Join(receivedDir, fmt.Sprintf("%s_%s", msg.ID, msg.FileName))
		err := decodeBase64ToFile(msg.BinaryData, outputPath)
		if err != nil {
			log.Printf("Error saving received file: %v", err)
			return
		}
		log.Printf("File saved to: %s", outputPath)
	} else {
		// Handle other message types
		switch msg.Action {
		case "create":
			log.Printf("Creating tablon: %s", msg.Content.Title)
			createOrUpdateMessage(msg)
		case "delete":
			log.Printf("Deleting tablon: %s", msg.TablonID)
			deleteTablon(msg.TablonID)
		case "delete_message":
			log.Printf("Deleting message: %s from tablon: %s", msg.ID, msg.TablonID)
			deleteMessage(msg.TablonID, msg.ID)
		case "like":
			log.Printf("Liking message: %s in tablon: %s", msg.ID, msg.TablonID)
			updateMessageLikes(msg.TablonID, msg.ID, msg.Content.Likes)
		default:
			log.Printf("Adding message to tablon: %s", msg.TablonID)
			createOrUpdateMessage(msg)
		}
	}

	// Store the message for API access
	messagesMutex.Lock()
	receivedMessages = append(receivedMessages, msg)
	messagesMutex.Unlock()
}
