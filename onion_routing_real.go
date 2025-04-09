package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"time"
)

// Estructura para representar una capa de enrutamiento cebolla
type OnionLayer struct {
	NextHop     string `json:"nextHop"`     // ID del siguiente nodo o "final"
	FinalDest   string `json:"finalDest"`   // ID del destino final
	LayerIndex  int    `json:"layerIndex"`  // Índice de la capa actual
	PayloadType string `json:"payloadType"` // Tipo de carga útil: "message" o "layer"
}

// Estructura para representar un mensaje de enrutamiento cebolla
type OnionMessage struct {
	Type       string `json:"type"`       // Tipo de mensaje: "onion"
	OriginNode string `json:"originNode"` // ID del nodo de origen
	CurrentHop string `json:"currentHop"` // ID del nodo actual
	Layer      []byte `json:"layer"`      // Capa cifrada para el nodo actual
	Payload    []byte `json:"payload"`    // Carga útil cifrada (siguiente capa o mensaje final)
}

// Inicializar el sistema de enrutamiento cebolla
func initOnionRouting(ctx context.Context) error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")

	// Inicializar el sistema de claves
	if err := initKeySystem(); err != nil {
		return fmt.Errorf("error al inicializar sistema de claves: %v", err)
	}

	// Inicializar el topic de control
	if err := initControlTopic(ctx); err != nil {
		return fmt.Errorf("error al inicializar topic de control: %v", err)
	}

	// Anunciar la presencia de este nodo
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
			case <-ctx.Done():
				return
			}
		}
	}()

	// Deshabilitar el enrutamiento de cebolla simulado
	disableRoutingHops = false

	log.Printf("Sistema de enrutamiento cebolla real inicializado correctamente")
	return nil
}

// Cifrar datos con AES-GCM
func encryptLayer(data []byte, key []byte) ([]byte, error) {
	// Asegurar que la clave tenga el tamaño correcto para AES-256
	hashedKey := sha256.Sum256(key)

	// Crear el cifrador AES
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	// Generar un nonce aleatorio
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Crear el modo GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Cifrar los datos
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	// Concatenar nonce y ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Descifrar datos con AES-GCM
func decryptLayer(data []byte, key []byte) ([]byte, error) {
	// Asegurar que la clave tenga el tamaño correcto para AES-256
	hashedKey := sha256.Sum256(key)

	// Verificar que los datos tengan al menos el tamaño del nonce
	if len(data) < 12 {
		return nil, fmt.Errorf("datos demasiado cortos")
	}

	// Extraer el nonce
	nonce := data[:12]
	ciphertext := data[12:]

	// Crear el cifrador AES
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	// Crear el modo GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Descifrar los datos
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Cifrar datos con RSA-OAEP
func encryptWithRSA(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
}

// Descifrar datos con RSA-OAEP
func decryptWithRSA(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, data, nil)
}

// Seleccionar una ruta aleatoria para un mensaje
func selectRandomRoute() ([]string, error) {
	// Obtener nodos disponibles
	availableNodes := getAvailableNodes()

	// Determinar el número de saltos (entre 2 y 4)
	minHops := 2
	maxHops := 4

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
	availableNodesCopy := make([]string, len(availableNodes))
	copy(availableNodesCopy, availableNodes)

	for i := 0; i < numHops; i++ {
		// Seleccionar un nodo aleatorio de los disponibles
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(availableNodesCopy))))
		route[i] = availableNodesCopy[idx.Int64()]

		// Eliminar el nodo seleccionado para evitar repeticiones
		availableNodesCopy = append(availableNodesCopy[:idx.Int64()], availableNodesCopy[idx.Int64()+1:]...)
	}

	return route, nil
}

// Crear un mensaje con enrutamiento cebolla
func createOnionRoutedMessage(originalMsg Message, route []string) ([]byte, error) {
	if len(route) < 1 {
		return nil, fmt.Errorf("la ruta debe tener al menos un nodo")
	}

	// Serializar el mensaje original
	originalMsgBytes, err := json.Marshal(originalMsg)
	if err != nil {
		return nil, fmt.Errorf("error al serializar mensaje original: %v", err)
	}

	// La carga útil inicial es el mensaje original
	currentPayload := originalMsgBytes

	// Construir las capas de enrutamiento cebolla (de adentro hacia afuera)
	for i := len(route) - 1; i >= 0; i-- {
		// Crear la capa para este nodo
		var nextHop string
		if i > 0 {
			nextHop = route[i-1]
		} else {
			nextHop = "final"
		}

		var payloadType string
		if i == len(route)-1 {
			payloadType = "message"
		} else {
			payloadType = "layer"
		}

		layer := OnionLayer{
			NextHop:     nextHop,
			FinalDest:   route[len(route)-1],
			LayerIndex:  i,
			PayloadType: payloadType,
		}

		// Serializar la capa
		layerBytes, err := json.Marshal(layer)
		if err != nil {
			return nil, fmt.Errorf("error al serializar capa: %v", err)
		}

		// Obtener la clave pública del nodo
		publicKey, err := getNodePublicKey(route[i])
		if err != nil {
			return nil, fmt.Errorf("error al obtener clave pública para nodo %s: %v", route[i], err)
		}

		// Cifrar la capa con RSA
		encryptedLayer, err := encryptWithRSA(layerBytes, publicKey)
		if err != nil {
			return nil, fmt.Errorf("error al cifrar capa para nodo %s: %v", route[i], err)
		}

		// Generar una clave AES aleatoria para cifrar la carga útil
		aesKey := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
			return nil, fmt.Errorf("error al generar clave AES: %v", err)
		}

		// Cifrar la carga útil con AES
		encryptedPayload, err := encryptLayer(currentPayload, aesKey)
		if err != nil {
			return nil, fmt.Errorf("error al cifrar carga útil: %v", err)
		}

		// Cifrar la clave AES con RSA
		encryptedKey, err := encryptWithRSA(aesKey, publicKey)
		if err != nil {
			return nil, fmt.Errorf("error al cifrar clave AES: %v", err)
		}

		// Crear el mensaje para este nodo
		onionMsg := OnionMessage{
			Type:       "onion",
			OriginNode: nodeID,
			CurrentHop: route[i],
			Layer:      encryptedLayer,
			Payload:    encryptedPayload,
		}

		// Añadir la clave cifrada al mensaje
		onionMsgMap := map[string]interface{}{
			"type":       "onion",
			"originNode": nodeID,
			"currentHop": route[i],
			"layer":      encryptedLayer,
			"payload":    encryptedPayload,
			"key":        encryptedKey,
		}

		// Serializar el mensaje
		onionMsgBytes, err := json.Marshal(onionMsgMap)
		if err != nil {
			return nil, fmt.Errorf("error al serializar mensaje onion: %v", err)
		}

		// La carga útil para la siguiente capa es este mensaje
		currentPayload = onionMsgBytes
	}

	return currentPayload, nil
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

	// Publicar el mensaje en el topic P2P
	if err := p2pTopic.Publish(context.Background(), onionMsg); err != nil {
		return fmt.Errorf("error al publicar mensaje: %v", err)
	}

	log.Printf("Mensaje enviado con enrutamiento cebolla real a través de %d nodos", len(route))
	return nil
}

// Procesar un mensaje de enrutamiento cebolla
func processOnionMessage(data []byte) error {
	// Deserializar el mensaje
	var onionMsg map[string]interface{}
	if err := json.Unmarshal(data, &onionMsg); err != nil {
		return fmt.Errorf("error al deserializar mensaje onion: %v", err)
	}

	// Verificar que sea un mensaje de enrutamiento cebolla
	msgType, ok := onionMsg["type"].(string)
	if !ok || msgType != "onion" {
		return fmt.Errorf("no es un mensaje de enrutamiento cebolla válido")
	}

	// Verificar que este nodo sea el destinatario actual
	currentHop, ok := onionMsg["currentHop"].(string)
	if !ok || currentHop != nodeID {
		return fmt.Errorf("este mensaje no es para este nodo")
	}

	// Extraer la capa cifrada
	layerBytes, ok := onionMsg["layer"].([]byte)
	if !ok {
		// Intentar convertir desde string base64
		layerStr, ok := onionMsg["layer"].(string)
		if !ok {
			return fmt.Errorf("formato de capa inválido")
		}
		var err error
		layerBytes, err = base64.StdEncoding.DecodeString(layerStr)
		if err != nil {
			return fmt.Errorf("error al decodificar capa: %v", err)
		}
	}

	// Extraer la clave cifrada
	keyBytes, ok := onionMsg["key"].([]byte)
	if !ok {
		// Intentar convertir desde string base64
		keyStr, ok := onionMsg["key"].(string)
		if !ok {
			return fmt.Errorf("formato de clave inválido")
		}
		var err error
		keyBytes, err = base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			return fmt.Errorf("error al decodificar clave: %v", err)
		}
	}

	// Extraer la carga útil cifrada
	payloadBytes, ok := onionMsg["payload"].([]byte)
	if !ok {
		// Intentar convertir desde string base64
		payloadStr, ok := onionMsg["payload"].(string)
		if !ok {
			return fmt.Errorf("formato de carga útil inválido")
		}
		var err error
		payloadBytes, err = base64.StdEncoding.DecodeString(payloadStr)
		if err != nil {
			return fmt.Errorf("error al decodificar carga útil: %v", err)
		}
	}

	// Descifrar la capa con la clave privada de este nodo
	decryptedLayerBytes, err := decryptWithRSA(layerBytes, nodePrivateKey)
	if err != nil {
		return fmt.Errorf("error al descifrar capa: %v", err)
	}

	// Deserializar la capa
	var layer OnionLayer
	if err := json.Unmarshal(decryptedLayerBytes, &layer); err != nil {
		return fmt.Errorf("error al deserializar capa: %v", err)
	}

	// Descifrar la clave AES con la clave privada de este nodo
	aesKey, err := decryptWithRSA(keyBytes, nodePrivateKey)
	if err != nil {
		return fmt.Errorf("error al descifrar clave AES: %v", err)
	}

	// Descifrar la carga útil con la clave AES
	decryptedPayload, err := decryptLayer(payloadBytes, aesKey)
	if err != nil {
		return fmt.Errorf("error al descifrar carga útil: %v", err)
	}

	// Verificar si somos el destino final
	if layer.NextHop == "final" {
		// Somos el destino final, procesar el mensaje original
		if layer.PayloadType != "message" {
			return fmt.Errorf("tipo de carga útil inválido para destino final: %s", layer.PayloadType)
		}

		var originalMsg Message
		if err := json.Unmarshal(decryptedPayload, &originalMsg); err != nil {
			return fmt.Errorf("error al deserializar mensaje original: %v", err)
		}

		// Procesar el mensaje original
		processP2PMessage(originalMsg)
		return nil
	}

	// No somos el destino final, reenviar al siguiente nodo
	nextHop := layer.NextHop

	// Reenviar la carga útil descifrada al siguiente nodo
	if err := p2pTopic.Publish(context.Background(), decryptedPayload); err != nil {
		return fmt.Errorf("error al reenviar mensaje al siguiente nodo: %v", err)
	}

	log.Printf("Mensaje reenviado al nodo %s", nextHop)
	return nil
}

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
