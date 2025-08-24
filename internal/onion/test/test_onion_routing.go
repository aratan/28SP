package onion_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aratan/api-p2p-front/internal/onion"
)

func TestOnionRouting() {
	// Configurar logging
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Iniciando prueba de enrutamiento cebolla...")

	// Inicializar sistema de claves para el nodo actual
	if err := onion.InitKeySystem(); err != nil {
		log.Fatalf("Error al inicializar sistema de claves: %v", err)
	}
	log.Printf("Nodo actual inicializado con ID: %s", onion.NodeID)

	// Simular otros nodos
	simulateOtherNodes()

	// Crear un mensaje de prueba
	testMessage := map[string]string{
		"content": "Este es un mensaje de prueba cifrado con enrutamiento cebolla",
		"time":    time.Now().Format(time.RFC3339),
	}

	// Seleccionar una ruta aleatoria
	route, err := onion.SelectRandomRoute(1, 3)
	if err != nil {
		log.Fatalf("Error al seleccionar ruta: %v", err)
	}
	log.Printf("Ruta seleccionada: %v", route)

	// Crear mensaje con enrutamiento cebolla
	onionMsg, err := onion.CreateOnionRoutedMessage(testMessage, route)
	if err != nil {
		log.Fatalf("Error al crear mensaje con enrutamiento cebolla: %v", err)
	}
	log.Printf("Mensaje con enrutamiento cebolla creado (tamaño: %d bytes)", len(onionMsg))

	// Simular el procesamiento del mensaje a través de la ruta
	simulateMessageProcessing(onionMsg, route)

	log.Println("Prueba de enrutamiento cebolla completada con éxito")
}

// simulateOtherNodes simula la existencia de otros nodos en la red
func simulateOtherNodes() {
	// Crear 5 nodos simulados
	for i := 0; i < 5; i++ {
		// Generar clave privada
		privateKey, err := generatePrivateKey()
		if err != nil {
			log.Printf("Error al generar clave para nodo simulado %d: %v", i, err)
			continue
		}

		// Generar ID del nodo
		nodeID := fmt.Sprintf("node-%d-%s", i, generateRandomID())

		// Registrar el nodo
		onion.KnownNodesMutex.Lock()
		onion.KnownNodes[nodeID] = &onion.OnionNode{
			ID:        nodeID,
			PublicKey: &privateKey.PublicKey,
			LastSeen:  time.Now(),
		}
		onion.KnownNodesMutex.Unlock()

		log.Printf("Nodo simulado registrado: %s", nodeID)
	}
}

// simulateMessageProcessing simula el procesamiento del mensaje a través de la ruta
func simulateMessageProcessing(onionMsg []byte, route []string) {
	log.Println("Simulando procesamiento del mensaje a través de la ruta...")

	// Decodificar el mensaje inicial
	var msg map[string]interface{}
	if err := json.Unmarshal(onionMsg, &msg); err != nil {
		log.Fatalf("Error al decodificar mensaje inicial: %v", err)
	}

	// Verificar que sea un mensaje de tipo onion
	msgType, ok := msg["type"].(string)
	if !ok || msgType != "onion" {
		log.Fatalf("No es un mensaje onion")
	}

	// Simular el procesamiento en cada nodo de la ruta
	currentMsg := onionMsg
	for i, nodeID := range route {
		log.Printf("Nodo %d (%s) procesando mensaje...", i+1, nodeID)

		// Simular el procesamiento en este nodo
		processedMsg, err := simulateNodeProcessing(currentMsg, nodeID)
		if err != nil {
			log.Fatalf("Error en nodo %d (%s): %v", i+1, nodeID, err)
		}

		// Actualizar el mensaje para el siguiente nodo
		currentMsg = processedMsg
	}

	// Verificar el mensaje final
	var finalMsg map[string]interface{}
	if err := json.Unmarshal(currentMsg, &finalMsg); err != nil {
		log.Fatalf("Error al decodificar mensaje final: %v", err)
	}

	log.Printf("Mensaje final recibido correctamente: %v", finalMsg)
}

// simulateNodeProcessing simula el procesamiento del mensaje en un nodo
func simulateNodeProcessing(msgData []byte, nodeID string) ([]byte, error) {
	// Decodificar el mensaje
	var msg map[string]interface{}
	if err := json.Unmarshal(msgData, &msg); err != nil {
		return nil, fmt.Errorf("error al decodificar mensaje: %v", err)
	}

	// Verificar que sea un mensaje de tipo onion
	msgType, ok := msg["type"].(string)
	if !ok || msgType != "onion" {
		return nil, fmt.Errorf("no es un mensaje onion")
	}

	// Verificar que este nodo sea el destinatario
	currentHop, ok := msg["currentHop"].(string)
	if !ok || currentHop != nodeID {
		return nil, fmt.Errorf("este nodo no es el destinatario del mensaje")
	}

	// Simular el procesamiento de la capa
	log.Printf("Nodo %s procesando su capa del mensaje", nodeID)

	// En una implementación real, aquí se descifraría la capa con la clave privada del nodo
	// y se procesaría según corresponda. Para esta simulación, simplemente devolvemos la carga útil.
	payload, ok := msg["payload"].([]byte)
	if !ok {
		return nil, fmt.Errorf("carga útil no encontrada o no es de tipo []byte")
	}

	return payload, nil
}

// generatePrivateKey genera una clave privada RSA
func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// generateRandomID genera un ID aleatorio
func generateRandomID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
