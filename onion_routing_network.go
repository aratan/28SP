package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"time"
)

// Variables para la red de enrutamiento cebolla
var (
	// Mínimo y máximo número de saltos para rutas
	minHops = 2
	maxHops = 4

	// Contexto para operaciones de red
	ctx = context.Background()
)

// Inicializar el sistema de enrutamiento cebolla
func initOnionRouting() error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")

	// Inicializar el sistema de gestión de claves
	if err := initKeyManagement(); err != nil {
		return fmt.Errorf("error al inicializar gestión de claves: %v", err)
	}

	// Deshabilitar el enrutamiento de cebolla simulado
	disableRoutingHops = false

	log.Printf("Sistema de enrutamiento cebolla real inicializado correctamente")
	return nil
}

// Iniciar la escucha de mensajes de enrutamiento cebolla
func startOnionListener() error {
	log.Println("Iniciando escucha de mensajes de enrutamiento cebolla...")

	// Anunciar la presencia de este nodo en la red
	if err := announceNode(); err != nil {
		return fmt.Errorf("error al anunciar nodo: %v", err)
	}

	// Programar anuncios periódicos
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := announceNode(); err != nil {
					log.Printf("Error al anunciar nodo periódicamente: %v", err)
				}
			}
		}
	}()

	return nil
}

// Seleccionar una ruta aleatoria para un mensaje
func selectRandomRoute() ([]string, error) {
	knownNodesMutex.RLock()
	defer knownNodesMutex.RUnlock()

	// Contar nodos disponibles (excluyendo este nodo)
	availableNodes := make([]string, 0, len(knownNodes)-1)
	for id := range knownNodes {
		if id != nodeID {
			availableNodes = append(availableNodes, id)
		}
	}

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
	for i := 0; i < numHops; i++ {
		// Seleccionar un nodo aleatorio de los disponibles
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(availableNodes))))
		route[i] = availableNodes[idx.Int64()]

		// Eliminar el nodo seleccionado para evitar repeticiones
		availableNodes = append(availableNodes[:idx.Int64()], availableNodes[idx.Int64()+1:]...)
	}

	return route, nil
}

// Publicar un mensaje usando enrutamiento cebolla real
func publishWithRealOnionRouting(msg Message) error {
	// Seleccionar una ruta aleatoria
	route, err := selectRandomRoute()
	if err != nil {
		return fmt.Errorf("error al seleccionar ruta: %v", err)
	}

	log.Printf("Ruta seleccionada: %v", route)

	// Crear el mensaje con enrutamiento cebolla
	onionMsg, err := createOnionRoutedMessage(msg, route)
	if err != nil {
		return fmt.Errorf("error al crear mensaje con enrutamiento cebolla: %v", err)
	}

	// Enviar el mensaje al primer nodo de la ruta
	if err := forwardToNode(route[0], onionMsg); err != nil {
		return fmt.Errorf("error al enviar mensaje al primer nodo: %v", err)
	}

	log.Printf("Mensaje enviado con enrutamiento cebolla real a través de %d nodos", len(route))
	return nil
}

// Reenviar un mensaje a un nodo específico
func forwardToNode(nodeID string, data []byte) error {
	// En una implementación real, enviaríamos el mensaje directamente al nodo
	// Por ahora, usamos el topic P2P general

	// Crear un mensaje de reenvío
	forwardMsg := map[string]interface{}{
		"type":      "forward",
		"target":    nodeID,
		"data":      data,
		"timestamp": time.Now().Unix(),
	}

	// Serializar el mensaje
	forwardMsgBytes, err := json.Marshal(forwardMsg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje de reenvío: %v", err)
	}

	// Publicar en el topic P2P
	if err := p2pTopic.Publish(ctx, forwardMsgBytes); err != nil {
		return fmt.Errorf("error al publicar mensaje de reenvío: %v", err)
	}

	log.Printf("Mensaje reenviado al nodo %s", nodeID)
	return nil
}

// Procesar un mensaje de reenvío
func processForwardMessage(data []byte) error {
	var forwardMsg map[string]interface{}
	if err := json.Unmarshal(data, &forwardMsg); err != nil {
		return fmt.Errorf("error al deserializar mensaje de reenvío: %v", err)
	}

	// Verificar que sea un mensaje de reenvío
	msgType, ok := forwardMsg["type"].(string)
	if !ok || msgType != "forward" {
		return fmt.Errorf("no es un mensaje de reenvío válido")
	}

	// Verificar que este nodo sea el destinatario
	target, ok := forwardMsg["target"].(string)
	if !ok || target != nodeID {
		return fmt.Errorf("este mensaje no es para este nodo")
	}

	// Extraer los datos
	msgData, ok := forwardMsg["data"].([]byte)
	if !ok {
		// Intentar convertir desde string base64
		msgDataStr, ok := forwardMsg["data"].(string)
		if !ok {
			return fmt.Errorf("formato de datos inválido en mensaje de reenvío")
		}

		var err error
		msgData, err = base64.StdEncoding.DecodeString(msgDataStr)
		if err != nil {
			return fmt.Errorf("error al decodificar datos: %v", err)
		}
	}

	// Procesar los datos como un mensaje de enrutamiento cebolla
	return processOnionMessage(msgData)
}

// Procesar un mensaje recibido
func processReceivedMessage(data []byte) {
	// Intentar decodificar como mensaje de anuncio de nodo
	var announcement map[string]interface{}
	if err := json.Unmarshal(data, &announcement); err == nil {
		msgType, ok := announcement["type"].(string)
		if ok && msgType == "node_announcement" {
			if err := processNodeAnnouncement(data); err != nil {
				log.Printf("Error al procesar anuncio de nodo: %v", err)
			}
			return
		}
	}

	// Intentar decodificar como mensaje de reenvío
	var forwardMsg map[string]interface{}
	if err := json.Unmarshal(data, &forwardMsg); err == nil {
		msgType, ok := forwardMsg["type"].(string)
		if ok && msgType == "forward" {
			if err := processForwardMessage(data); err != nil {
				log.Printf("Error al procesar mensaje de reenvío: %v", err)
			}
			return
		}
	}

	// Intentar decodificar como mensaje de enrutamiento cebolla
	var onionMsg OnionMessage
	if err := json.Unmarshal(data, &onionMsg); err == nil {
		if onionMsg.Type == "onion" && onionMsg.CurrentHop == nodeID {
			if err := processOnionMessage(data); err != nil {
				log.Printf("Error al procesar mensaje de enrutamiento cebolla: %v", err)
			}
			return
		}
	}

	// Si no es ninguno de los anteriores, intentar procesar como mensaje normal
	var msg Message
	if err := json.Unmarshal(data, &msg); err == nil {
		if msg.OnionRouted {
			// Es un mensaje con enrutamiento cebolla, pero no para este nodo
			return
		}

		// Procesar como mensaje normal
		processP2PMessage(msg)
		return
	}
}
