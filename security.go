package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"time"
)

// Función para cifrar datos con AES-GCM
func secureEncrypt(plaintext, key []byte) ([]byte, error) {
	// Asegurar que la clave tenga el tamaño correcto para AES-256
	hashedKey := sha256.Sum256(key)
	
	// Crear el cifrador AES
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, fmt.Errorf("error al crear cifrador AES: %v", err)
	}
	
	// Crear el modo GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error al crear GCM: %v", err)
	}
	
	// Crear un nonce aleatorio
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error al generar nonce: %v", err)
	}
	
	// Cifrar y autenticar el mensaje
	// El formato es: nonce + ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	
	return ciphertext, nil
}

// Función para descifrar datos con AES-GCM
func secureDecrypt(ciphertext, key []byte) ([]byte, error) {
	// Asegurar que la clave tenga el tamaño correcto para AES-256
	hashedKey := sha256.Sum256(key)
	
	// Crear el cifrador AES
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, fmt.Errorf("error al crear cifrador AES: %v", err)
	}
	
	// Crear el modo GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error al crear GCM: %v", err)
	}
	
	// Verificar que el ciphertext sea lo suficientemente largo
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext demasiado corto")
	}
	
	// Extraer el nonce y el ciphertext real
	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	
	// Descifrar el mensaje
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("error al descifrar: %v", err)
	}
	
	return plaintext, nil
}

// Función para ocultar información sensible del mensaje
func anonymizeMessage(msg Message) Message {
	// Crear una copia para no modificar el original
	anonymized := msg
	
	// Ocultar información del remitente si es necesario
	if anonymized.From.Username != "" && anonymized.AnonymousSender {
		// Generar un alias para el nombre de usuario
		hash := sha256.Sum256([]byte(anonymized.From.Username))
		anonymized.From.Username = fmt.Sprintf("anon_%x", hash[:4])
		
		// Eliminar foto de perfil
		anonymized.From.Photo = ""
		
		// Ocultar PeerID
		if anonymized.From.PeerID != "" {
			anonymized.From.PeerID = fmt.Sprintf("hidden_%x", hash[4:8])
		}
	}
	
	return anonymized
}

// Función para serializar y cifrar un mensaje con múltiples capas
func secureSerializeMessage(msg Message, keys [][]byte) ([]byte, error) {
	// Ocultar información sensible antes de serializar
	msg = anonymizeMessage(msg)
	
	// Serializar el mensaje a JSON
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("error al serializar: %v", err)
	}
	
	// Si no hay claves, usar cifrado base64 simple
	if len(keys) == 0 {
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(msgBytes)))
		base64.StdEncoding.Encode(encoded, msgBytes)
		return encoded, nil
	}
	
	// Aplicar múltiples capas de cifrado (onion routing)
	ciphertext := msgBytes
	for _, key := range keys {
		ciphertext, err = secureEncrypt(ciphertext, key)
		if err != nil {
			return nil, fmt.Errorf("error en capa de cifrado: %v", err)
		}
	}
	
	return ciphertext, nil
}

// Función para descifrar y deserializar un mensaje
func secureDeserializeMessage(data []byte, keys [][]byte) (Message, error) {
	// Si no hay claves, intentar decodificar base64
	if len(keys) == 0 {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(decoded, data)
		if err == nil {
			var msg Message
			if json.Unmarshal(decoded[:n], &msg) == nil {
				return msg, nil
			}
		}
		// Si falla, intentar deserializar directamente
		var msg Message
		if err := json.Unmarshal(data, &msg); err == nil {
			return msg, nil
		}
		return Message{}, fmt.Errorf("no se pudo deserializar el mensaje")
	}
	
	// Aplicar múltiples capas de descifrado en orden inverso
	plaintext := data
	var lastErr error
	
	// Intentar descifrar con todas las combinaciones posibles de claves
	// Esto es importante para la resistencia a la censura y el anonimato
	for i := len(keys) - 1; i >= 0; i-- {
		decrypted, err := secureDecrypt(plaintext, keys[i])
		if err != nil {
			lastErr = err
			continue
		}
		
		// Intentar deserializar
		var msg Message
		if err := json.Unmarshal(decrypted, &msg); err == nil {
			log.Printf(Green+"Mensaje descifrado exitosamente"+Reset)
			return msg, nil
		}
		
		// Si no se pudo deserializar, podría ser que necesita más capas de descifrado
		plaintext = decrypted
	}
	
	// Si llegamos aquí, intentar deserializar el último plaintext
	var msg Message
	if err := json.Unmarshal(plaintext, &msg); err == nil {
		return msg, nil
	}
	
	// Último recurso: intentar deserializar directamente
	if err := json.Unmarshal(data, &msg); err == nil {
		return msg, nil
	}
	
	return Message{}, fmt.Errorf("no se pudo descifrar o deserializar: %v", lastErr)
}

// Función para generar rutas aleatorias para el enrutamiento de cebolla
func generateRandomRoutes(minHops, maxHops int) []string {
	// Generar un número aleatorio entre minHops y maxHops
	random, _ := rand.Int(rand.Reader, big.NewInt(int64(maxHops-minHops+1)))
	numHops := minHops + int(random.Int64())
	
	// Crear el slice para las rutas
	routes := make([]string, numHops)
	
	// Generar IDs de nodo aleatorios
	for i := 0; i < numHops; i++ {
		// Generar un ID de nodo aleatorio
		hash := sha256.Sum256([]byte(fmt.Sprintf("node-%d-%d", i, time.Now().UnixNano())))
		routes[i] = hex.EncodeToString(hash[:8])
	}
	
	return routes
}

// Función para actualizar el mensaje con opciones de seguridad
func secureMessage(msg *Message, config SecurityConfig) {
	// Añadir rutas aleatorias para mejorar el anonimato (onion routing)
	if config.OnionRouting && msg.RoutingHops == nil {
		msg.RoutingHops = generateRandomRoutes(config.MinHops, config.MaxHops)
	}
	
	// Marcar el mensaje como cifrado si está habilitado
	if config.EndToEndEncryption {
		msg.Encrypted = true
	}
	
	// Marcar el mensaje como anónimo si está habilitado
	if config.AnonymousMessages {
		msg.AnonymousSender = true
	}
}
