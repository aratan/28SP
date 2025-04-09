package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Variables globales para el enrutamiento cebolla
var (
	// Clave privada de este nodo
	nodePrivateKey *rsa.PrivateKey

	// ID de este nodo
	nodeID string

	// Mapa de nodos conocidos (ID -> clave pública)
	knownNodes      = make(map[string]*rsa.PublicKey)
	knownNodesMutex sync.RWMutex
)

// Inicializar el sistema de enrutamiento cebolla
func initOnionRouting() error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")

	// Crear directorio para claves si no existe
	keysDir := "onion_keys"
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return fmt.Errorf("error al crear directorio para claves: %v", err)
	}

	// Comprobar si ya tenemos una clave privada
	privateKeyPath := filepath.Join(keysDir, "private_key.pem")
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		// Generar un nuevo par de claves RSA
		log.Println("Generando nuevo par de claves RSA...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("error al generar clave RSA: %v", err)
		}

		// Guardar la clave privada
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		if err := ioutil.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
			return fmt.Errorf("error al guardar clave privada: %v", err)
		}

		// Guardar la clave pública
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("error al serializar clave pública: %v", err)
		}

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		publicKeyPath := filepath.Join(keysDir, "public_key.pem")
		if err := ioutil.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
			return fmt.Errorf("error al guardar clave pública: %v", err)
		}

		nodePrivateKey = privateKey
	} else {
		// Cargar clave privada existente
		log.Println("Cargando clave privada existente...")
		privateKeyPEM, err := ioutil.ReadFile(privateKeyPath)
		if err != nil {
			return fmt.Errorf("error al leer clave privada: %v", err)
		}

		block, _ := pem.Decode(privateKeyPEM)
		if block == nil {
			return fmt.Errorf("error al decodificar clave privada PEM")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("error al parsear clave privada: %v", err)
		}

		nodePrivateKey = privateKey
	}

	// Calcular el ID del nodo a partir de la clave pública
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&nodePrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error al serializar clave pública: %v", err)
	}

	hash := sha256.Sum256(publicKeyBytes)
	nodeID = fmt.Sprintf("%x", hash[:8])

	log.Printf("ID del nodo: %s", nodeID)

	// Registrar este nodo en el mapa de nodos conocidos
	knownNodesMutex.Lock()
	knownNodes[nodeID] = &nodePrivateKey.PublicKey
	knownNodesMutex.Unlock()

	// Deshabilitar el enrutamiento de cebolla simulado
	disableRoutingHops = false

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

// Anunciar la presencia de este nodo en la red
func announceNode() error {
	// Convertir la clave pública a formato PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&nodePrivateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error al serializar clave pública: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Crear mensaje de anuncio
	announcement := map[string]interface{}{
		"type":      "node_announcement",
		"nodeID":    nodeID,
		"publicKey": base64.StdEncoding.EncodeToString(publicKeyPEM),
		"timestamp": time.Now().Unix(),
	}

	// Serializar y publicar
	announcementBytes, err := json.Marshal(announcement)
	if err != nil {
		return fmt.Errorf("error al serializar anuncio: %v", err)
	}

	// Publicar usando el topic P2P existente
	err = p2pTopic.Publish(context.Background(), announcementBytes)
	if err != nil {
		return fmt.Errorf("error al anunciar nodo: %v", err)
	}

	log.Printf("Nodo anunciado en la red: %s", nodeID)
	return nil
}

// Procesar un anuncio de nodo
func processNodeAnnouncement(data []byte) error {
	var announcement map[string]interface{}
	if err := json.Unmarshal(data, &announcement); err != nil {
		return fmt.Errorf("error al decodificar anuncio: %v", err)
	}

	// Verificar que sea un anuncio de nodo
	msgType, ok := announcement["type"].(string)
	if !ok || msgType != "node_announcement" {
		return fmt.Errorf("no es un anuncio de nodo válido")
	}

	// Extraer ID del nodo
	nodeID, ok := announcement["nodeID"].(string)
	if !ok {
		return fmt.Errorf("anuncio sin ID de nodo")
	}

	// Extraer clave pública
	publicKeyStr, ok := announcement["publicKey"].(string)
	if !ok {
		return fmt.Errorf("anuncio sin clave pública")
	}

	// Decodificar la clave pública
	publicKeyPEM, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		return fmt.Errorf("error al decodificar clave pública: %v", err)
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("error al decodificar clave pública PEM")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error al parsear clave pública: %v", err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("clave pública no es de tipo RSA")
	}

	// Registrar el nodo
	knownNodesMutex.Lock()
	knownNodes[nodeID] = publicKey
	knownNodesMutex.Unlock()

	log.Printf("Nodo registrado: %s", nodeID)
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
	for i := 0; i < numHops; i++ {
		// Seleccionar un nodo aleatorio de los disponibles
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(availableNodes))))
		route[i] = availableNodes[idx.Int64()]

		// Eliminar el nodo seleccionado para evitar repeticiones
		availableNodes = append(availableNodes[:idx.Int64()], availableNodes[idx.Int64()+1:]...)
	}

	return route, nil
}

// Cifrar datos con la clave pública de un nodo
func encryptForNode(nodeID string, data []byte) ([]byte, error) {
	knownNodesMutex.RLock()
	publicKey, exists := knownNodes[nodeID]
	knownNodesMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("nodo desconocido: %s", nodeID)
	}

	// Usar cifrado híbrido (AES + RSA) para mensajes grandes
	// Generar una clave AES aleatoria
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("error al generar clave AES: %v", err)
	}

	// Cifrar la clave AES con RSA
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error al cifrar clave AES: %v", err)
	}

	// Cifrar los datos con AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("error al crear cifrador AES: %v", err)
	}

	// Generar un nonce aleatorio
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error al generar nonce: %v", err)
	}

	// Crear el modo GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error al crear modo GCM: %v", err)
	}

	// Cifrar los datos
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)

	// Combinar todo: [longitud de clave cifrada (2 bytes)][clave cifrada][nonce][datos cifrados]
	result := make([]byte, 2+len(encryptedKey)+len(nonce)+len(ciphertext))
	result[0] = byte(len(encryptedKey) >> 8)
	result[1] = byte(len(encryptedKey))
	copy(result[2:], encryptedKey)
	copy(result[2+len(encryptedKey):], nonce)
	copy(result[2+len(encryptedKey)+len(nonce):], ciphertext)

	return result, nil
}

// Descifrar datos con la clave privada de este nodo
func decryptWithNodeKey(data []byte) ([]byte, error) {
	// Extraer la longitud de la clave cifrada
	if len(data) < 2 {
		return nil, fmt.Errorf("datos demasiado cortos")
	}
	keyLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+keyLen+12 {
		return nil, fmt.Errorf("datos demasiado cortos para contener clave y nonce")
	}

	// Extraer la clave cifrada
	encryptedKey := data[2 : 2+keyLen]

	// Extraer el nonce
	nonce := data[2+keyLen : 2+keyLen+12]

	// Extraer los datos cifrados
	ciphertext := data[2+keyLen+12:]

	// Descifrar la clave AES con RSA
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, nodePrivateKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("error al descifrar clave AES: %v", err)
	}

	// Descifrar los datos con AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("error al crear cifrador AES: %v", err)
	}

	// Crear el modo GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error al crear modo GCM: %v", err)
	}

	// Descifrar los datos
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error al descifrar datos: %v", err)
	}

	return plaintext, nil
}

// Estructura para representar una capa de enrutamiento cebolla
type OnionLayerData struct {
	NextHop     string `json:"nextHop"`     // ID del siguiente nodo
	FinalDest   string `json:"finalDest"`   // ID del destino final
	PayloadType string `json:"payloadType"` // Tipo de carga útil: "message" o "layer"
}

// Estructura para representar un mensaje de enrutamiento cebolla
type OnionMessageData struct {
	Type        string `json:"type"`        // Tipo de mensaje: "onion"
	OriginNode  string `json:"originNode"`  // ID del nodo de origen
	CurrentHop  string `json:"currentHop"`  // ID del nodo actual
	Layer       []byte `json:"layer"`       // Capa cifrada para el nodo actual
	Payload     []byte `json:"payload"`     // Carga útil cifrada (siguiente capa o mensaje final)
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

		layer := OnionLayerData{
			NextHop:     nextHop,
			FinalDest:   route[len(route)-1],
			PayloadType: payloadType,
		}

		// Serializar la capa
		layerBytes, err := json.Marshal(layer)
		if err != nil {
			return nil, fmt.Errorf("error al serializar capa: %v", err)
		}

		// Cifrar la capa para este nodo
		encryptedLayer, err := encryptForNode(route[i], layerBytes)
		if err != nil {
			return nil, fmt.Errorf("error al cifrar capa para nodo %s: %v", route[i], err)
		}

		// Crear el mensaje para este nodo
		onionMsg := OnionMessageData{
			Type:       "onion",
			OriginNode: nodeID,
			CurrentHop: route[i],
			Layer:      encryptedLayer,
			Payload:    currentPayload,
		}

		// Serializar el mensaje
		onionMsgBytes, err := json.Marshal(onionMsg)
		if err != nil {
			return nil, fmt.Errorf("error al serializar mensaje onion: %v", err)
		}

		// La carga útil para la siguiente capa es este mensaje
		currentPayload = onionMsgBytes

		// Si no es el primer nodo, cifrar la carga útil para el siguiente nodo
		if i > 0 {
			currentPayload, err = encryptForNode(route[i-1], currentPayload)
			if err != nil {
				return nil, fmt.Errorf("error al cifrar carga útil para nodo %s: %v", route[i-1], err)
			}
		}
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

// Procesar un mensaje recibido
func processReceivedMessage(data []byte) {
	// Intentar decodificar como anuncio de nodo
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

	// Intentar decodificar como mensaje de enrutamiento cebolla
	var onionMsg OnionMessageData
	if err := json.Unmarshal(data, &onionMsg); err == nil {
		if onionMsg.Type == "onion" && onionMsg.CurrentHop == nodeID {
			if err := processOnionMessage(data); err != nil {
				log.Printf("Error al procesar mensaje de enrutamiento cebolla: %v", err)
			}
			return
		}
	}

	// Si no es ninguno de los anteriores, intentar procesar como mensaje normal
	msg, err := SecureDeserializeMessageFix(data, p2pKeys)
	if err != nil {
		log.Printf("Error al deserializar mensaje: %v", err)
		return
	}

	// Procesar como mensaje normal
	processP2PMessage(msg)
}

// Procesar un mensaje de enrutamiento cebolla
func processOnionMessage(data []byte) error {
	// Deserializar el mensaje
	var onionMsg OnionMessageData
	if err := json.Unmarshal(data, &onionMsg); err != nil {
		return fmt.Errorf("error al deserializar mensaje onion: %v", err)
	}

	// Verificar que este nodo sea el destinatario actual
	if onionMsg.CurrentHop != nodeID {
		return fmt.Errorf("este mensaje no es para este nodo")
	}

	// Descifrar la capa con la clave privada de este nodo
	layerBytes, err := decryptWithNodeKey(onionMsg.Layer)
	if err != nil {
		return fmt.Errorf("error al descifrar capa: %v", err)
	}

	// Deserializar la capa
	var layer OnionLayerData
	if err := json.Unmarshal(layerBytes, &layer); err != nil {
		return fmt.Errorf("error al deserializar capa: %v", err)
	}

	// Verificar si somos el destino final
	if layer.NextHop == "final" {
		// Somos el destino final, procesar el mensaje original
		var originalMsg Message
		if err := json.Unmarshal(onionMsg.Payload, &originalMsg); err != nil {
			return fmt.Errorf("error al deserializar mensaje original: %v", err)
		}

		// Procesar el mensaje original
		processP2PMessage(originalMsg)
		return nil
	}

	// No somos el destino final, reenviar al siguiente nodo
	nextHop := layer.NextHop

	// Crear el mensaje para el siguiente nodo
	nextMsg := OnionMessageData{
		Type:       "onion",
		OriginNode: onionMsg.OriginNode,
		CurrentHop: nextHop,
		Layer:      nil, // Se llenará en el siguiente nodo
		Payload:    onionMsg.Payload,
	}

	// Serializar y enviar el mensaje
	nextMsgBytes, err := json.Marshal(nextMsg)
	if err != nil {
		return fmt.Errorf("error al serializar mensaje para siguiente nodo: %v", err)
	}

	// Publicar en el topic P2P
	if err := p2pTopic.Publish(context.Background(), nextMsgBytes); err != nil {
		return fmt.Errorf("error al publicar mensaje para siguiente nodo: %v", err)
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
