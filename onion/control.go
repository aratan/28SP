package onion

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// Variables globales para el topic de control
// Nota: Las variables globales para el topic de control ahora están definidas en shared.go

// Inicializar el topic de control
func InitControlTopic(ctx context.Context, ps *pubsub.PubSub) error {
	log.Println("Inicializando topic de control...")

	// Crear el topic de control
	var err error
	ControlTopic, err = ps.Join("p2p-control")
	if err != nil {
		return fmt.Errorf("error al unirse al topic de control: %v", err)
	}

	// Suscribirse al topic de control
	ControlSub, err = ControlTopic.Subscribe()
	if err != nil {
		return fmt.Errorf("error al suscribirse al topic de control: %v", err)
	}

	// Iniciar la escucha de mensajes de control
	go HandleControlMessages(ctx)

	log.Println("Topic de control inicializado correctamente")
	return nil
}

// Manejar mensajes del topic de control
func HandleControlMessages(ctx context.Context) {
	for {
		msg, err := ControlSub.Next(ctx)
		if err != nil {
			log.Printf("Error al recibir mensaje de control: %v", err)
			continue
		}

		// Procesar el mensaje de control
		go ProcessControlMessage(msg.Data)
	}
}

// Procesar un mensaje de control
func ProcessControlMessage(data []byte) {
	// Decodificar el mensaje
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("Error al decodificar mensaje de control: %v", err)
		return
	}

	// Obtener el tipo de mensaje
	msgType, ok := msg["type"].(string)
	if !ok {
		log.Printf("Mensaje de control sin tipo")
		return
	}

	// Procesar según el tipo de mensaje
	switch msgType {
	case MsgTypeNodeAnnouncement:
		ProcessNodeAnnouncement(msg)
	case MsgTypeKeyExchange:
		ProcessKeyExchange(msg)
	case MsgTypeRouteUpdate:
		ProcessRouteUpdate(msg)
	case MsgTypeNetworkStatus:
		ProcessNetworkStatus(msg)
	default:
		log.Printf("Tipo de mensaje de control desconocido: %s", msgType)
	}
}

// Procesar un anuncio de nodo
func ProcessNodeAnnouncement(msg map[string]interface{}) {
	// Extraer ID del nodo
	nodeID, ok := msg["nodeID"].(string)
	if !ok {
		log.Printf("Anuncio de nodo sin ID")
		return
	}

	// Extraer clave pública
	publicKeyStr, ok := msg["publicKey"].(string)
	if !ok {
		log.Printf("Anuncio de nodo sin clave pública")
		return
	}

	// Decodificar la clave pública
	publicKey, err := StringToPublicKey(publicKeyStr)
	if err != nil {
		log.Printf("Error al procesar clave pública: %v", err)
		return
	}

	// Registrar el nodo
	KnownNodesMutex.Lock()
	KnownNodes[nodeID] = publicKey
	KnownNodesMutex.Unlock()

	log.Printf("Nodo registrado: %s", nodeID)
}

// Procesar un intercambio de claves
func ProcessKeyExchange(msg map[string]interface{}) {
	// Implementación del intercambio de claves
	log.Printf("Procesando intercambio de claves")
}

// Procesar una actualización de ruta
func ProcessRouteUpdate(msg map[string]interface{}) {
	// Extraer destino
	dest, ok := msg["destination"].(string)
	if !ok {
		log.Printf("Actualización de ruta sin destino")
		return
	}

	// Extraer ruta
	routeInterface, ok := msg["route"].([]interface{})
	if !ok {
		log.Printf("Actualización de ruta sin ruta")
		return
	}

	// Convertir la ruta a []string
	route := make([]string, len(routeInterface))
	for i, nodeInterface := range routeInterface {
		nodeID, ok := nodeInterface.(string)
		if !ok {
			log.Printf("ID de nodo inválido en ruta")
			return
		}
		route[i] = nodeID
	}

	// Registrar la ruta
	KnownRoutesMutex.Lock()
	KnownRoutes[dest] = route
	KnownRoutesMutex.Unlock()

	log.Printf("Ruta actualizada para destino %s: %v", dest, route)
}

// Procesar un estado de red
func ProcessNetworkStatus(msg map[string]interface{}) {
	// Implementación del procesamiento de estado de red
	log.Printf("Procesando estado de red")
}

// Anunciar la presencia de este nodo en la red
func AnnounceNode() error {
	// Convertir la clave pública a formato PEM
	publicKeyStr := PublicKeyToString(&NodePrivateKey.PublicKey)

	// Crear mensaje de anuncio
	announcement := map[string]interface{}{
		"type":      MsgTypeNodeAnnouncement,
		"nodeID":    NodeID,
		"publicKey": publicKeyStr,
		"timestamp": time.Now().Unix(),
	}

	// Serializar y publicar
	announcementBytes, err := json.Marshal(announcement)
	if err != nil {
		return fmt.Errorf("error al serializar anuncio: %v", err)
	}

	// Publicar en el topic de control
	err = ControlTopic.Publish(context.Background(), announcementBytes)
	if err != nil {
		return fmt.Errorf("error al anunciar nodo: %v", err)
	}

	log.Printf("Nodo anunciado en la red: %s", NodeID)
	return nil
}

// Publicar una actualización de ruta
func PublishRouteUpdate(dest string, route []string) error {
	// Crear mensaje de actualización de ruta
	routeUpdate := map[string]interface{}{
		"type":        MsgTypeRouteUpdate,
		"destination": dest,
		"route":       route,
		"timestamp":   time.Now().Unix(),
	}

	// Serializar y publicar
	routeUpdateBytes, err := json.Marshal(routeUpdate)
	if err != nil {
		return fmt.Errorf("error al serializar actualización de ruta: %v", err)
	}

	// Publicar en el topic de control
	err = ControlTopic.Publish(context.Background(), routeUpdateBytes)
	if err != nil {
		return fmt.Errorf("error al publicar actualización de ruta: %v", err)
	}

	log.Printf("Actualización de ruta publicada para destino %s: %v", dest, route)
	return nil
}
