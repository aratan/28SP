package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// GenerateObfuscatedTimestamp genera una marca de tiempo con precisión reducida
// y ruido aleatorio para dificultar la correlación temporal
func GenerateObfuscatedTimestamp() string {
	// Obtener la hora actual
	now := time.Now()

	// Reducir la precisión a intervalos de 5 minutos
	minutes := now.Minute()
	roundedMinutes := (minutes / 5) * 5

	// Crear una nueva hora con minutos redondeados y segundos a cero
	roundedTime := time.Date(
		now.Year(), now.Month(), now.Day(),
		now.Hour(), roundedMinutes, 0, 0,
		now.Location(),
	)

	// Añadir ruido aleatorio de -2 a +2 minutos
	noise, _ := rand.Int(rand.Reader, big.NewInt(5))
	noiseMinutes := noise.Int64() - 2
	noisyTime := roundedTime.Add(time.Duration(noiseMinutes) * time.Minute)

	// Formatear la hora según RFC3339
	return noisyTime.Format(time.RFC3339)
}

// ObfuscateFileName oculta metadatos en nombres de archivo
func ObfuscateFileName(originalName string) string {
	// Generar un ID aleatorio para el archivo
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	randomID := fmt.Sprintf("%x", randomBytes)

	// Extraer la extensión del archivo original
	parts := strings.Split(originalName, ".")
	extension := ""
	if len(parts) > 1 {
		extension = "." + parts[len(parts)-1]
	}

	// Crear un nuevo nombre que no revele el original
	return fmt.Sprintf("file_%s%s", randomID, extension)
}

// AddMessagePadding añade padding aleatorio a los mensajes para ocultar su tamaño real
func AddMessagePadding(message string, minPadding, maxPadding int) string {
	// Determinar la cantidad de padding a añadir
	paddingSize, _ := rand.Int(rand.Reader, big.NewInt(int64(maxPadding-minPadding+1)))
	paddingSize = paddingSize.Add(paddingSize, big.NewInt(int64(minPadding)))

	// Generar el padding
	padding := make([]byte, paddingSize.Int64())
	rand.Read(padding)

	// Convertir el padding a una cadena hexadecimal
	paddingStr := fmt.Sprintf("<!-- %x -->", padding)

	// Añadir el padding al mensaje
	return message + paddingStr
}

// AnonymizeMessageMetadata mejora la anonimización de metadatos en los mensajes
func AnonymizeMessageMetadata(msg Message) Message {
	// Crear una copia para no modificar el original
	anonymized := msg

	// Ocultar información del remitente
	if anonymized.From.Username != "" {
		// Generar un alias para el nombre de usuario
		// Siempre anonimizar, no solo cuando AnonymousSender es true
		hash := sha256Sum([]byte(anonymized.From.Username))
		anonymized.From.Username = fmt.Sprintf("anon_%x", hash[:4])

		// Eliminar foto de perfil
		anonymized.From.Photo = ""

		// Ocultar PeerID
		if anonymized.From.PeerID != "" {
			anonymized.From.PeerID = fmt.Sprintf("hidden_%x", hash[4:8])
		}
	}

	// Usar marca de tiempo obfuscada
	anonymized.Timestamp = GenerateObfuscatedTimestamp()

	// Si el mensaje tiene contenido, añadir padding
	if anonymized.Content.Message != "" {
		anonymized.Content.Message = AddMessagePadding(anonymized.Content.Message, 10, 100)
	}

	return anonymized
}

// Función auxiliar para calcular SHA-256
func sha256Sum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
