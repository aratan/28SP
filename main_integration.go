package main

import (
	"context"
	"log"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// Función principal para inicializar y usar el enrutamiento cebolla real
func InitializeAndUseOnionRouting(ctx context.Context, ps *pubsub.PubSub, p2pTopic *pubsub.Topic, p2pSub *pubsub.Subscription) {
	// Asignar las variables globales
	PS = ps
	P2PTopic = p2pTopic
	P2PSub = p2pSub

	// Inicializar el enrutamiento cebolla real
	if err := InitRealOnionRouting(ctx); err != nil {
		log.Printf(Red+"Error al inicializar el sistema de enrutamiento cebolla real: %v"+Reset, err)
		log.Printf(Yellow+"Usando enrutamiento cebolla simulado como fallback"+Reset)
	} else {
		log.Printf(Green+"Sistema de enrutamiento cebolla real inicializado correctamente"+Reset)
	}

	// Iniciar la escucha de mensajes P2P
	go HandleP2PMessages(ctx)
}

// HandleP2PMessages maneja los mensajes P2P recibidos
func HandleP2PMessages(ctx context.Context) {
	log.Printf("Iniciando manejador de mensajes P2P...")
	for {
		log.Printf("Esperando mensajes P2P...")
		m, err := P2PSub.Next(ctx)
		if err != nil {
			log.Printf("Failed to get next message: %v", err)
			continue
		}
		// Log the message data size before deserialization
		log.Printf("Received message from %s, data size: %d bytes", m.ReceivedFrom, len(m.Message.Data))

		// Procesar el mensaje con posible enrutamiento cebolla
		isOnionMessage, msg := ProcessReceivedMessage(m.Message.Data)
		if isOnionMessage {
			// El mensaje fue procesado por el sistema de enrutamiento cebolla
			continue
		}

		// Procesar el mensaje normal
		ProcessP2PMessage(msg)
	}
}

// ProcessP2PMessage procesa un mensaje P2P normal
func ProcessP2PMessage(msg Message) {
	// Implementación de la función ProcessP2PMessage
	// Esta es una implementación ficticia, debes reemplazarla con la implementación real
	log.Printf("Procesando mensaje P2P: %s", msg.ID)

	// Verificar si el mensaje es para este nodo
	if msg.To != "all" && msg.To != GetNodeID() {
		log.Printf("Mensaje no destinado a este nodo. Destino: %s", msg.To)
		return
	}

	// Añadir el mensaje a la lista de mensajes recibidos
	MessagesMutex.Lock()
	ReceivedMessages = append(ReceivedMessages, msg)
	MessagesMutex.Unlock()

	log.Printf("Mensaje procesado y añadido a la lista de mensajes recibidos")
}

// GetNodeID devuelve el ID de este nodo
func GetNodeID() string {
	// Implementación de la función GetNodeID
	// Esta es una implementación ficticia, debes reemplazarla con la implementación real
	return "node1"
}

// SendMessage envía un mensaje usando el enrutamiento cebolla real
func SendMessage(msg Message) {
	// Publicar el mensaje con enrutamiento cebolla real
	PublishMessageWithOnionRouting(msg)
}

// Ejemplo de uso del enrutamiento cebolla real
func ExampleUsage() {
	// Crear un mensaje
	msg := Message{
		ID: GenerateMessageID(),
		From: UserInfo{
			Username: "user1",
		},
		To:        "all",
		TablonID:  "tablon1",
		Content: Content{
			Title:   "Título del mensaje",
			Message: "Contenido del mensaje",
		},
		Timestamp: time.Now().Unix(),
	}

	// Enviar el mensaje con enrutamiento cebolla real
	SendMessage(msg)
}
