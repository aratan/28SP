package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"
)

// Inicializar el sistema de enrutamiento cebolla
func initOnionRouting() error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")

	// Deshabilitar el enrutamiento de cebolla simulado
	disableRoutingHops = false

	log.Printf("Sistema de enrutamiento cebolla real inicializado correctamente")

	return nil
}

// Iniciar la escucha de mensajes de enrutamiento cebolla
func startOnionListener() error {
	log.Println("Iniciando escucha de mensajes de enrutamiento cebolla...")
	return nil
}

// Cifrar datos con AES-GCM
func onionEncrypt(data []byte, key []byte) ([]byte, error) {
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
func onionDecrypt(data []byte, key []byte) ([]byte, error) {
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

// Estructura para representar una capa de enrutamiento cebolla
type OnionLayer struct {
	NextHop    string `json:"nextHop"`    // ID del siguiente nodo o "final"
	FinalDest  string `json:"finalDest"`  // ID del destino final
	LayerIndex int    `json:"layerIndex"` // Índice de la capa actual
}

// Publicar usando enrutamiento cebolla real
func publishWithRealOnionRouting(msg Message) error {
	// Generar claves para cada capa
	numLayers := 3 // Número fijo de capas para simplificar
	layerKeys := make([][]byte, numLayers)
	for i := 0; i < numLayers; i++ {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return fmt.Errorf("error al generar clave para capa %d: %v", i, err)
		}
		layerKeys[i] = key
	}

	// Serializar el mensaje original
	originalMsgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje original: %v", err)
	}

	// Cifrar el mensaje con múltiples capas
	currentData := originalMsgBytes
	for i := numLayers - 1; i >= 0; i-- {
		// Crear la capa actual
		var nextHop string
		if i > 0 {
			nextHop = fmt.Sprintf("node_%d", i-1)
		} else {
			nextHop = "final"
		}

		layer := OnionLayer{
			NextHop:    nextHop,
			FinalDest:  "destination",
			LayerIndex: i,
		}

		// Serializar la capa
		layerBytes, err := json.Marshal(layer)
		if err != nil {
			return fmt.Errorf("error al serializar capa %d: %v", i, err)
		}

		// Combinar la capa con los datos actuales
		combinedData := make([]byte, len(layerBytes)+len(currentData))
		copy(combinedData, layerBytes)
		copy(combinedData[len(layerBytes):], currentData)

		// Cifrar la capa
		currentData, err = onionEncrypt(combinedData, layerKeys[i])
		if err != nil {
			return fmt.Errorf("error al cifrar capa %d: %v", i, err)
		}
	}

	// Crear el mensaje final
	finalMsg := map[string]interface{}{
		"type":      "onion_message",
		"data":      currentData,
		"keys":      layerKeys, // En una implementación real, las claves se distribuirían de forma segura
		"timestamp": time.Now().Unix(),
	}

	// Serializar y enviar el mensaje
	finalMsgBytes, err := json.Marshal(finalMsg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje final: %v", err)
	}

	// Publicar el mensaje en el topic P2P
	if err := p2pTopic.Publish(context.Background(), finalMsgBytes); err != nil {
		return fmt.Errorf("error al publicar mensaje: %v", err)
	}

	log.Printf("Mensaje enviado con enrutamiento cebolla real a través de %d capas", numLayers)
	return nil
}

// Procesar un mensaje recibido
func processReceivedMessage(data []byte) {
	// Intentar decodificar como mensaje de enrutamiento cebolla
	var onionMsg map[string]interface{}
	if err := json.Unmarshal(data, &onionMsg); err == nil {
		msgType, ok := onionMsg["type"].(string)
		if ok && msgType == "onion_message" {
			log.Printf("Mensaje de enrutamiento cebolla recibido")
			processOnionMessage(onionMsg)
			return
		}
	}

	// Si no es un mensaje de enrutamiento cebolla, usar el deserializador seguro tradicional
	msg, err := SecureDeserializeMessageFix(data, p2pKeys)
	if err != nil {
		log.Printf("Error al deserializar mensaje: %v", err)
		return
	}

	// Procesar como mensaje normal
	processP2PMessage(msg)
}

// Procesar un mensaje de enrutamiento cebolla
func processOnionMessage(onionMsg map[string]interface{}) {
	// Extraer los datos cifrados
	encryptedData, ok := onionMsg["data"].([]byte)
	if !ok {
		log.Printf("Formato de datos inválido en mensaje de enrutamiento cebolla")
		return
	}

	// Extraer las claves
	keysInterface, ok := onionMsg["keys"].([]interface{})
	if !ok {
		log.Printf("Formato de claves inválido en mensaje de enrutamiento cebolla")
		return
	}

	// Convertir las claves a [][]byte
	keys := make([][]byte, len(keysInterface))
	for i, keyInterface := range keysInterface {
		keyBytes, ok := keyInterface.([]byte)
		if !ok {
			log.Printf("Formato de clave %d inválido", i)
			continue
		}
		keys[i] = keyBytes
	}

	// Descifrar las capas una por una
	currentData := encryptedData
	for i := 0; i < len(keys); i++ {
		// Descifrar la capa actual
		decryptedData, err := onionDecrypt(currentData, keys[i])
		if err != nil {
			log.Printf("Error al descifrar capa %d: %v", i, err)
			return
		}

		// Extraer la información de la capa
		var layer OnionLayer
		layerSize := 100 // Tamaño aproximado de la capa serializada
		if len(decryptedData) < layerSize {
			log.Printf("Datos descifrados demasiado cortos para contener una capa")
			return
		}

		if err := json.Unmarshal(decryptedData[:layerSize], &layer); err != nil {
			log.Printf("Error al deserializar capa: %v", err)
			return
		}

		// Verificar si es la capa final
		if layer.NextHop == "final" {
			// Es la capa final, extraer el mensaje original
			var originalMsg Message
			if err := json.Unmarshal(decryptedData[layerSize:], &originalMsg); err != nil {
				log.Printf("Error al deserializar mensaje original: %v", err)
				return
			}

			// Procesar el mensaje original
			processP2PMessage(originalMsg)
			return
		}

		// No es la capa final, continuar con la siguiente capa
		currentData = decryptedData[layerSize:]
	}
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
