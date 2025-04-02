package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath" // Necesario para filepath.Join
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go" // Considerar migrar a github.com/golang-jwt/jwt/v4 o v5
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network" // Importado para network.Connected
	"github.com/libp2p/go-libp2p/core/peer"
	mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"   // *** AÑADIDO IMPORT para TLS explícito ***
	libp2ptcp "github.com/libp2p/go-libp2p/p2p/transport/tcp" // *** AÑADIDO IMPORT para TCP explícito ***
	"gopkg.in/yaml.v2"
)

// --- Global Variables ---

var (
	// Flag deprecado si se usa config.yaml, pero se mantiene por si acaso
	topicNameFlag = flag.String("topicName", "applesauce", "name of topic to join (overridden by config.yaml)")
	// Usar una clave segura y preferiblemente desde variables de entorno o config
	jwtSecretKey = []byte("your-256-bit-secret") // ¡Cambiar esto por una clave segura!
)

var (
	p2pTopic *pubsub.Topic
	p2pSub   *pubsub.Subscription
	p2pKeys  [][]byte // Clave(s) para encriptación de mensajes P2P
)

// Colores para logs
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Reset  = "\033[0m"
)

// --- Struct Definitions ---

// Config representa la estructura del archivo config.yaml
type Config struct {
	TopicName      string `yaml:"topicName"`
	EncryptionKey  string `yaml:"encryptionKey"` // Clave AES-256 en formato hexadecimal (64 caracteres)
	LogLevel       string `yaml:"logLevel"`      // No implementado actualmente
	ListenAddress  string `yaml:"listenAddress"` // Dirección de escucha para P2P (ej: /ip4/0.0.0.0/tcp/4001)
	WebServerAddr  string `yaml:"webServerAddr"` // Dirección para el servidor web (ej: :8080 o :8443)
	MaxMessageSize int    `yaml:"maxMessageSize"`
	LogFile        string `yaml:"logFile"` // No implementado actualmente
	RetryInterval  int    `yaml:"retryInterval"`
	Mdns           struct {
		Enabled    bool   `yaml:"enabled"`
		ServiceTag string `yaml:"serviceTag"`
	} `yaml:"mdns"`
	UseSSL bool `yaml:"useSSL"` // Flag para habilitar TLS en el servidor web
	CertFile string `yaml:"certFile"` // Path al archivo cert.pem
	KeyFile  string `yaml:"keyFile"`  // Path al archivo key.pem
	Users  []struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"` // Considerar almacenar hashes en lugar de texto plano
	} `yaml:"users"`
}

// Message representa la estructura de un mensaje en la red P2P y API
type Message struct {
	ID         string   `json:"id"`
	From       UserInfo `json:"from"`
	To         string   `json:"to"` // "BROADCAST" o PeerID específico
	Timestamp  string   `json:"timestamp"`
	Content    Content  `json:"content"`
	Action     string   `json:"action"` // "create", "delete", "like", "binary_transfer", etc.
	TablonID   string   `json:"tablonId,omitempty"` // ID del tablón al que pertenece (si aplica)
	BinaryData string   `json:"binaryData,omitempty"` // Datos binarios codificados en Base64
	FileName   string   `json:"fileName,omitempty"`   // Nombre del archivo binario
}

// Tablon representa un tablón de anuncios
type Tablon struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Messages []Message `json:"messages"`
	Geo      string    `json:"geo,omitempty"`
}

// UserInfo contiene información básica del remitente/usuario
type UserInfo struct {
	PeerID   string `json:"peerId"`
	Username string `json:"username"`
	Photo    string `json:"photo,omitempty"` // URL o Base64 de la foto
}

// Content contiene el payload principal del mensaje
type Content struct {
	Title      string    `json:"title,omitempty"`
	Message    string    `json:"message,omitempty"`
	Subtitle   string    `json:"subtitle,omitempty"`
	Likes      int       `json:"likes"`
	Comments   []Comment `json:"comments,omitempty"`
	Subscribed bool      `json:"subscribed"` // No claro su uso actual
}

// Comment representa un comentario en un mensaje
type Comment struct {
	Username string `json:"username"`
	Comment  string `json:"comment"`
}

// --- Global State ---

var tablones []Tablon
var tablonesMutex sync.Mutex // Protege el acceso a 'tablones'

var receivedMessages []Message // Deprecado si los mensajes se asocian a tablones
var messagesMutex sync.Mutex    // Protege el acceso a 'receivedMessages'

// --- Configuration ---

// readConfig lee y parsea el archivo config.yaml
func readConfig() (*Config, error) {
	data, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return nil, fmt.Errorf("error reading config.yaml: %w", err)
	}
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling config.yaml: %w", err)
	}

	// Valores por defecto si no están en el config
	if config.WebServerAddr == "" {
		config.WebServerAddr = ":8080" // Puerto HTTP por defecto
		if config.UseSSL {
			config.WebServerAddr = ":8443" // Puerto HTTPS por defecto
		}
	}
    if config.CertFile == "" && config.UseSSL {
        config.CertFile = "cert.pem" // Default cert file name
    }
    if config.KeyFile == "" && config.UseSSL {
        config.KeyFile = "key.pem" // Default key file name
    }
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = 1 << 20 // 1 MiB por defecto
	}
	if config.RetryInterval == 0 {
		config.RetryInterval = 500 // ms por defecto
	}
    if config.EncryptionKey == "" {
        log.Println(Yellow + "Warning: P2P EncryptionKey is empty in config.yaml. Messages will not be encrypted." + Reset)
        p2pKeys = nil // Asegurarse de que sea nil si está vacío
    } else {
        // Validar formato de la clave de encriptación P2P (hexadecimal de 64 chars)
		keyBytes, err := hex.DecodeString(config.EncryptionKey)
		if err != nil || len(keyBytes) != 32 { // AES-256 necesita 32 bytes
			return nil, fmt.Errorf("invalid EncryptionKey in config.yaml: must be a 64-character hex string (representing 32 bytes), got %d chars, error: %v", len(config.EncryptionKey), err)
		}
        p2pKeys = [][]byte{keyBytes} // Establecer la clave global
        log.Println(Blue+"P2P encryption key loaded successfully."+Reset)
    }

	return &config, nil
}

// --- Utility Functions ---

// generateMessageID crea un ID único para mensajes o tablones
func generateMessageID() string {
	// Usar algo más robusto como UUID en producción si es necesario
	return fmt.Sprintf("id_%d", time.Now().UnixNano())
}

// encodeFileToBase64 lee un archivo y lo codifica en Base64
func encodeFileToBase64(filePath string) (string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// decodeBase64ToFile decodifica una cadena Base64 y la escribe en un archivo
func decodeBase64ToFile(base64String, outputPath string) error {
	data, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return fmt.Errorf("failed to decode base64 string: %w", err)
	}
	err = ioutil.WriteFile(outputPath, data, 0644) // Permisos rw-r--r--
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", outputPath, err)
	}
	return nil
}

// --- HTTP Handlers ---

// sendBinaryHandler maneja la subida de archivos y los envía por P2P
func sendBinaryHandler(w http.ResponseWriter, r *http.Request) {
    // Verificar JWT si se requiere autenticación para subir archivos
	if !verifyJWT(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := getClaimsFromToken(r)
    if claims == nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
    }
    // Extraer info del usuario de forma segura
    peerId, okPeer := claims["peerId"].(string)
    username, okUser := claims["username"].(string)
    photo, okPhoto := claims["photo"].(string)
    if !okPeer || !okUser || !okPhoto {
         log.Printf(Red + "Error extracting user info from JWT claims" + Reset)
         http.Error(w, "Invalid token claims", http.StatusUnauthorized)
         return
    }
    userInfo := UserInfo{PeerID: peerId, Username: username, Photo: photo}

	// Limitar tamaño del request body
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20) // Limite de 100 MB (ajustar según necesidad)

	err := r.ParseMultipartForm(32 << 20) // 32 MB max memoria para parsear, resto a disco
	if err != nil {
		http.Error(w, fmt.Sprintf("Error parsing multipart form: %v", err), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file") // "file" es el nombre del campo en el form-data
	if err != nil {
		http.Error(w, "Error retrieving the file from form-data", http.StatusBadRequest)
		return
	}
	defer file.Close()

	log.Printf("Receiving file: %s, Size: %d bytes", header.Filename, header.Size)

	// Crear un archivo temporal seguro
	tempFile, err := ioutil.TempFile("", "upload-*.tmp")
	if err != nil {
		log.Printf(Red+"Error creating temporary file: %v"+Reset, err)
		http.Error(w, "Error creating temporary file", http.StatusInternalServerError)
		return
	}
	tempFilePath := tempFile.Name()
	// Asegurarse de borrar el temporal incluso si hay errores después
	defer os.Remove(tempFilePath)

	// Copiar el contenido al archivo temporal
	fileBytes, err := io.Copy(tempFile, file)
	if err != nil {
		log.Printf(Red+"Error copying uploaded file to temp: %v"+Reset, err)
		http.Error(w, "Error saving the file", http.StatusInternalServerError)
		return
	}
	// Es importante cerrar el archivo *antes* de intentar leerlo de nuevo para codificarlo
	err = tempFile.Close()
    if err != nil {
        log.Printf(Red+"Error closing temporary file after write: %v"+Reset, err)
        // Podría continuar, pero es una señal de alerta
    }


	log.Printf("File saved temporarily to: %s, Bytes written: %d", tempFilePath, fileBytes)


	// Codificar el archivo temporal a base64
	base64Data, err := encodeFileToBase64(tempFilePath)
	if err != nil {
		log.Printf(Red+"Error encoding file to base64: %v"+Reset, err)
		http.Error(w, "Error encoding file to base64", http.StatusInternalServerError)
		return
	}


	// Crear el mensaje P2P
	msg := Message{
		ID:        generateMessageID(),
		From:      userInfo, // Usar info del token JWT
		To:        "BROADCAST", // O enviar a un peer específico si se proporciona
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    "binary_transfer",
		BinaryData: base64Data,
		FileName:   header.Filename,
	}

	// Publicar en P2P (no bloquear la respuesta HTTP)
	go publishToP2P(msg)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "file queued for P2P transfer", "messageId": msg.ID, "fileName": msg.FileName})
}


// createTablonHandler crea un nuevo tablón y lo anuncia por P2P
func createTablonHandler(w http.ResponseWriter, r *http.Request) {
	if !verifyJWT(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := getClaimsFromToken(r)
    if claims == nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
    }
    peerId, okPeer := claims["peerId"].(string)
    username, okUser := claims["username"].(string)
    photo, okPhoto := claims["photo"].(string)
    if !okPeer || !okUser || !okPhoto {
         log.Printf(Red + "Error extracting user info from JWT claims" + Reset)
         http.Error(w, "Invalid token claims", http.StatusUnauthorized)
         return
    }
    userInfo := UserInfo{PeerID: peerId, Username: username, Photo: photo}


	tablonName := r.URL.Query().Get("name")
	if tablonName == "" {
		http.Error(w, "Missing 'name' query parameter", http.StatusBadRequest)
		return
	}
	mensajeInicial := r.URL.Query().Get("mensaje") // Mensaje opcional al crear
	geo := r.URL.Query().Get("geo")         // Geo opcional

	tablonID := generateMessageID() // ID único para el tablón

	// Crear el mensaje inicial (si existe) para P2P
    // Este mensaje anuncia la creación del tablón
	msg := Message{
		ID:        generateMessageID(), // ID del mensaje, no del tablón
		From:      userInfo,
		To:        "BROADCAST",
		Timestamp: time.Now().Format(time.RFC3339),
		Content:   Content{Title: tablonName, Message: mensajeInicial, Subtitle: "Tablon Creado"},
		Action:    "create_tablon", // Acción específica para crear tablón
		TablonID:  tablonID,        // Asociar con el ID del tablón
	}

	// Publicar anuncio de creación en P2P
	go publishToP2P(msg)

	// Crear el Tablón localmente
	tablon := Tablon{
		ID:       tablonID,
		Name:     tablonName,
		Messages: []Message{}, // Inicialmente vacío o con el primer mensaje si se desea
		Geo:      geo,
	}
    // Si hubo mensaje inicial, añadirlo también localmente
    if mensajeInicial != "" {
        initialContentMsg := Message{
            ID:        generateMessageID(),
            From:      userInfo,
            To:        tablonID, // Dirigido al tablón
            Timestamp: time.Now().Format(time.RFC3339),
            Content:   Content{Title: "Inicio", Message: mensajeInicial},
            Action:    "create", // Acción de crear mensaje normal
            TablonID:  tablonID,
        }
        tablon.Messages = append(tablon.Messages, initialContentMsg)
        // Opcionalmente, publicar este mensaje también por P2P si se quiere que otros lo vean inmediatamente
        // go publishToP2P(initialContentMsg)
    }


	tablonesMutex.Lock()
	tablones = append(tablones, tablon)
	tablonesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "tablon created",
		"id":      tablon.ID,
		"name":    tablon.Name,
        "message": "Tablon created and announced via P2P.",
	})
}

// addMessageToTablonHandler añade un mensaje a un tablón existente y lo publica por P2P
func addMessageToTablonHandler(w http.ResponseWriter, r *http.Request) {
    if !verifyJWT(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims := getClaimsFromToken(r)
    if claims == nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
    }
    peerId, okPeer := claims["peerId"].(string)
    username, okUser := claims["username"].(string)
    photo, okPhoto := claims["photo"].(string)
    if !okPeer || !okUser || !okPhoto {
         log.Printf(Red + "Error extracting user info from JWT claims" + Reset)
         http.Error(w, "Invalid token claims", http.StatusUnauthorized)
         return
    }
    userInfo := UserInfo{PeerID: peerId, Username: username, Photo: photo}

	tablonID := r.URL.Query().Get("tablon_id")
	if tablonID == "" {
		http.Error(w, "Missing 'tablon_id' query parameter", http.StatusBadRequest)
		return
	}

	messageContent := r.URL.Query().Get("message")
	if messageContent == "" {
		http.Error(w, "Missing 'message' query parameter", http.StatusBadRequest)
		return
	}
    title := r.URL.Query().Get("title") // Título opcional para el mensaje

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	var tablonFound *Tablon = nil
	for i := range tablones {
		if tablones[i].ID == tablonID {
            tablonFound = &tablones[i]
			break
		}
	}

    if tablonFound == nil {
        http.Error(w, "Tablon not found", http.StatusNotFound)
        return
    }

    // Crear el mensaje
    msg := Message{
        ID:        generateMessageID(),
        From:      userInfo,
        To:        "BROADCAST", // O al tablonID si se usa como destino P2P
        Timestamp: time.Now().Format(time.RFC3339),
        Content:   Content{Title: title, Message: messageContent},
        Action:    "create", // Acción de crear mensaje
        TablonID:  tablonID,
    }

    // Añadir localmente
    tablonFound.Messages = append(tablonFound.Messages, msg)

    // Publicar en la red P2P
    go publishToP2P(msg)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"status": "message added", "messageId": msg.ID})
}

// readTablonHandler devuelve la lista de tablones (o uno específico)
func readTablonHandler(w http.ResponseWriter, r *http.Request) {
	// Opcional: Permitir leer un tablón específico por ID
	tablonID := r.URL.Query().Get("id")

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	if tablonID != "" {
		for _, tablon := range tablones {
			if tablon.ID == tablonID {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tablon)
				return
			}
		}
		http.Error(w, "Tablon not found", http.StatusNotFound)
		return
	}

	// Si no se pide ID específico, devolver todos
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tablones)
}

// deleteTablonHandler elimina un tablón localmente y anuncia la eliminación por P2P
func deleteTablonHandler(w http.ResponseWriter, r *http.Request) {
	if !verifyJWT(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
    claims := getClaimsFromToken(r)
    if claims == nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
    }
    // Opcional: Verificar si el usuario tiene permiso para borrar este tablón
    peerId, okPeer := claims["peerId"].(string)
    username, okUser := claims["username"].(string)
    photo, okPhoto := claims["photo"].(string)
    if !okPeer || !okUser || !okPhoto {
         log.Printf(Red + "Error extracting user info from JWT claims" + Reset)
         http.Error(w, "Invalid token claims", http.StatusUnauthorized)
         return
    }
    userInfo := UserInfo{PeerID: peerId, Username: username, Photo: photo}

	tablonID := r.URL.Query().Get("id")
	if tablonID == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	// Crear mensaje P2P para anunciar la eliminación
	msg := Message{
		ID:        tablonID, // Usar el ID del tablón como identificador de la acción
		From:      userInfo,
		To:        "BROADCAST",
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    "delete_tablon", // Acción específica
		TablonID:  tablonID,
	}
	go publishToP2P(msg)

	// Eliminar localmente
	tablonesMutex.Lock()
	originalLength := len(tablones)
	filteredTablones := []Tablon{}
	for _, tablon := range tablones {
		if tablon.ID != tablonID {
			filteredTablones = append(filteredTablones, tablon)
		}
	}
    tablones = filteredTablones
	tablonesMutex.Unlock()

	if len(tablones) == originalLength {
		http.Error(w, "Tablon not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "tablon deleted", "id": tablonID})
}

// deleteMessageHandler elimina un mensaje de un tablón y anuncia por P2P
func deleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	if !verifyJWT(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
    claims := getClaimsFromToken(r)
     if claims == nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
    }
    // Opcional: Verificar permisos del usuario para borrar el mensaje
    peerId, okPeer := claims["peerId"].(string)
    username, okUser := claims["username"].(string)
    photo, okPhoto := claims["photo"].(string)
    if !okPeer || !okUser || !okPhoto {
         log.Printf(Red + "Error extracting user info from JWT claims" + Reset)
         http.Error(w, "Invalid token claims", http.StatusUnauthorized)
         return
    }
    userInfo := UserInfo{PeerID: peerId, Username: username, Photo: photo}

	tablonID := r.URL.Query().Get("tablonId")
	messageID := r.URL.Query().Get("messageId")

	if tablonID == "" || messageID == "" {
		http.Error(w, "Missing 'tablonId' or 'messageId' query parameter", http.StatusBadRequest)
		return
	}

	// Anunciar eliminación por P2P
	msg := Message{
		ID:        messageID, // ID del mensaje a eliminar
		From:      userInfo,
		To:        "BROADCAST",
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    "delete", // Acción genérica de borrar mensaje
		TablonID:  tablonID,
	}
	go publishToP2P(msg)


	// Eliminar localmente
	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

    messageDeleted := false
	for i, tablon := range tablones {
		if tablon.ID == tablonID {
            filteredMessages := []Message{}
			for _, message := range tablon.Messages {
				if message.ID != messageID {
					filteredMessages = append(filteredMessages, message)
				} else {
                    messageDeleted = true
                }
			}
            // Actualizar la lista de mensajes del tablón
            if messageDeleted {
                tablones[i].Messages = filteredMessages
                 w.Header().Set("Content-Type", "application/json")
			    json.NewEncoder(w).Encode(map[string]string{"status": "message deleted", "tablonId": tablonID, "messageId": messageID})
			    return // Salir si se encontró y eliminó
            } else {
                // El mensaje no se encontró en este tablón
                http.Error(w, "Message not found in the specified tablon", http.StatusNotFound)
                return
            }
		}
	}

	// Si el bucle termina, el tablón no se encontró
	http.Error(w, "Tablon not found", http.StatusNotFound)
}


// likeMessageHandler incrementa el contador de likes de un mensaje y lo anuncia por P2P
func likeMessageHandler(w http.ResponseWriter, r *http.Request) {
    // Opcional: Añadir verificación JWT si dar like requiere login
    /*
	if !verifyJWT(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
    claims := getClaimsFromToken(r)
    userInfo := UserInfo{ PeerID: claims["peerId"].(string), ... }
    */

	tablonID := r.URL.Query().Get("tablonId")
	messageID := r.URL.Query().Get("messageId")

	if tablonID == "" || messageID == "" {
		http.Error(w, "Missing 'tablonId' or 'messageId' query parameter", http.StatusBadRequest)
		return
	}

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	var updatedLikes int = -1 // Inicializar a -1 para saber si se encontró

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			for j, message := range tablon.Messages {
				if message.ID == messageID {
					// Incrementar localmente
					tablones[i].Messages[j].Content.Likes++
					updatedLikes = tablones[i].Messages[j].Content.Likes

					// Crear y anunciar mensaje de 'like' por P2P
					likeMsg := Message{
						ID:        messageID, // ID del mensaje que recibió el like
						// From: userInfo, // Si se requiere autenticación
                        From: UserInfo{Username: "AnonLike"}, // Placeholder si no hay auth
						To:        "BROADCAST",
						Timestamp: time.Now().Format(time.RFC3339),
						Content:   Content{Likes: updatedLikes}, // Solo enviar el nuevo contador
						Action:    "like",
						TablonID:  tablonID,
					}
					go publishToP2P(likeMsg) // Anunciar el like

					break // Salir del bucle de mensajes
				}
			}
			if updatedLikes != -1 {
				break // Salir del bucle de tablones si ya se encontró y actualizó
			}
		}
	}

	if updatedLikes == -1 {
		http.Error(w, "Message or Tablon not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "message liked",
		"likes":  updatedLikes,
        "tablonId": tablonID,
        "messageId": messageID,
	})
}


// --- Authentication & Authorization ---

// validateCredentials verifica usuario/contraseña contra config.yaml
func validateCredentials(username, password string) bool {
	config, err := readConfig() // Volver a leer o cachear config? Leer cada vez es simple pero menos eficiente.
	if err != nil {
		log.Printf(Red+"Failed to read config for validation: %v"+Reset, err)
		return false
	}

	for _, user := range config.Users {
		// ¡Comparación insegura! Usar hash y salt en producción.
		if user.Username == username && user.Password == password {
			return true
		}
	}
	log.Printf(Yellow+"Login attempt failed for username: %s"+Reset, username)
	return false
}

// generateTokenHandler crea un token JWT si las credenciales son válidas
func generateTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed (use POST)", http.StatusMethodNotAllowed)
		return
	}

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
		// Incluir PeerId y Photo en el login es inusual. ¿Se generan aquí o el cliente los envía?
		// Asumamos que el cliente los envía para incluirlos en el token.
		PeerId   string `json:"peerId"` // ¿De dónde viene este ID? ¿El ID del nodo libp2p del cliente?
		Photo    string `json:"photo"`  // URL a la foto del usuario
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if credentials.Username == "" || credentials.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Validar credenciales (¡Usar Hashing en producción!)
	if !validateCredentials(credentials.Username, credentials.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Crear Claims para el token JWT
	claims := jwt.MapClaims{
		"authorized": true,
		"username":   credentials.Username,
		"peerId":     credentials.PeerId, // Incluir si es necesario
		"photo":      credentials.Photo,  // Incluir si es necesario
		"exp":        time.Now().Add(time.Hour * 24).Unix(), // Token expira en 24 horas
		"iat":        time.Now().Unix(),                   // Issued at
	}

	// Crear token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Firmar token con la clave secreta
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		log.Printf(Red+"Error signing token: %v"+Reset, err)
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
        "username": credentials.Username, // Devolver info útil
        "peerId": credentials.PeerId,
	})
}

// verifyJWT valida el token JWT presente en la cabecera Authorization
func verifyJWT(r *http.Request) bool {
	tokenString := r.Header.Get("Authorization")
	// Espera formato "Bearer <token>"
	if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer ") {
		return false
	}
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validar algoritmo de firma
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Devolver la clave secreta
		return jwtSecretKey, nil
	})

	if err != nil {
		// No loguear cada token inválido como error necesariamente, podría ser normal
		// log.Printf(Yellow+"JWT validation error: %v"+Reset, err)
		return false
	}

	// Verificar si el token es válido y contiene claims
	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true
	}

	return false
}

// getClaimsFromToken extrae los claims de un token válido
func getClaimsFromToken(r *http.Request) jwt.MapClaims {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer ") {
		return nil
	}
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Solo necesitamos parsear, la validación se hizo en verifyJWT (o se puede repetir aquí)
		return jwtSecretKey, nil
	})

    // Verificar validez de nuevo por si acaso
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims
	}

	return nil
}

// --- Deprecated Handlers (Mantener si aún se usan, considerar eliminar) ---

// sendMessageHandler (parece genérico, ¿cuál es su propósito ahora con tablones?)
func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(Yellow + "Warning: /api/send endpoint called (potentially deprecated)" + Reset)
	// Este handler parece redundante con addMessageToTablonHandler.
	// Si es para mensajes generales no asociados a tablones, necesita lógica P2P.
    // Asumiendo que es un handler antiguo/de prueba:
	messageContent := r.URL.Query().Get("message")
	if messageContent == "" {
		http.Error(w, "Missing 'message' query parameter", http.StatusBadRequest)
		return
	}

    // Crear un mensaje genérico (sin tablón)
	msg := Message{
		ID:        generateMessageID(),
		From:      UserInfo{PeerID: "legacy_sender", Username: "Legacy System"},
		To:        "BROADCAST",
		Timestamp: time.Now().Format(time.RFC3339),
		Content: Content{
			Title:      r.URL.Query().Get("title"),
			Message:    messageContent,
			Subtitle:   r.URL.Query().Get("subtitle"),
		},
        Action: "legacy_message",
	}

    // Publicar si es necesario
    // go publishToP2P(msg)

    // Guardar localmente (si es necesario)
	messagesMutex.Lock()
	receivedMessages = append(receivedMessages, msg) // Usa la lista global antigua
	messagesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "legacy message received", "id": msg.ID})
}

// receiveMessagesHandler (devuelve la lista global 'receivedMessages')
func receiveMessagesHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(Yellow + "Warning: /api/recibe endpoint called (potentially deprecated)" + Reset)
	messagesMutex.Lock()
	defer messagesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(receivedMessages) // Devuelve la lista global antigua
}


// --- P2P Communication ---

// publishToP2P serializa, encripta (si hay claves) y publica un mensaje en el topic P2P
func publishToP2P(msg Message) {
	if p2pTopic == nil {
		log.Println(Red + "Error: P2P Topic is not initialized. Cannot publish." + Reset)
		return
	}

	// Serializar y encriptar
	serializedMsg, err := serializeAndEncryptMessage(msg, p2pKeys)
	if err != nil {
		log.Printf(Red+"Failed to serialize/encrypt message for P2P: %v"+Reset, err)
		return
	}

	// Publicar con reintentos
    config, err := readConfig() // Leer config para obtener RetryInterval
    if err != nil {
        log.Printf(Yellow+"Warning: Could not read config for P2P publish retry interval: %v. Using default."+Reset, err)
    }
    retryInterval := 500 // Default si falla lectura de config
    if config != nil && config.RetryInterval > 0 { // Usar valor de config si es válido
        retryInterval = config.RetryInterval
    }
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // Timeout para cada intento
		err = p2pTopic.Publish(ctx, serializedMsg)
		cancel() // Liberar recursos del contexto
		if err == nil {
			log.Printf(Green+"Message published to P2P topic (Action: %s, ID: %s)"+Reset, msg.Action, msg.ID)
			return // Éxito
		}
		log.Printf(Yellow+"P2P publish error (attempt %d/%d): %v. Retrying in %d ms..."+Reset, i+1, maxRetries, err, retryInterval)
		time.Sleep(time.Duration(retryInterval) * time.Millisecond)
		retryInterval *= 2 // Backoff exponencial simple
	}
	log.Printf(Red+"Failed to publish message to P2P after %d attempts (Action: %s, ID: %s)"+Reset, maxRetries, msg.Action, msg.ID)
}

// handleP2PMessages escucha continuamente mensajes del topic P2P, los desencripta y procesa
func handleP2PMessages(ctx context.Context) {
	if p2pSub == nil {
		log.Println(Red + "Error: P2P Subscription is not initialized. Cannot handle messages." + Reset)
		return
	}
	log.Println(Blue + "P2P message handler started. Listening for messages..." + Reset)

	for {
		m, err := p2pSub.Next(ctx)
		if err != nil {
            if ctx.Err() != nil { // Verificar si el contexto fue cancelado
                log.Println(Yellow+"P2P subscription context canceled or deadline exceeded. Exiting handler."+Reset)
                return
            }
			// Errores de suscripción pueden ser serios
			log.Printf(Red+"ERROR: Failed to get next P2P message: %v. Subscription might be broken."+Reset, err)
            // Considerar lógica de reconexión o terminar el programa si la subscripción falla persistentemente
            time.Sleep(5 * time.Second) // Esperar antes de reintentar
			continue
		}

		// Ignorar mensajes propios (si no se configuró en GossipSub)
		// Necesitaría acceso al host 'h' aquí para comparar h.ID()
		// if m.ReceivedFrom == h.ID() { continue }

		// Desencriptar y deserializar
		msg, err := decryptAndDeserializeMessage(m.Message.GetData(), p2pKeys)
		if err != nil {
			// No fatal, podría ser un mensaje corrupto o con clave incorrecta
			log.Printf(Yellow+"P2P message deserialization/decryption error from %s: %v"+Reset, m.ReceivedFrom.ShortString(), err)
			continue // Ignorar mensaje inválido
		}

        // Log del mensaje recibido
		log.Printf(Blue+"[P2P RX] Action: %s, ID: %s, TablonID: %s, From: %s (%s)" + Reset,
            msg.Action, msg.ID, msg.TablonID, msg.From.Username, m.ReceivedFrom.ShortString())


		// Procesar el mensaje según su acción
		processP2PMessage(msg)
	}
}


// processP2PMessage actualiza el estado local (tablones, mensajes) según el mensaje P2P recibido
func processP2PMessage(msg Message) {
	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	switch msg.Action {
	case "create_tablon":
		// Crear el tablón si no existe
        tablonExists := false
        for _, t := range tablones {
            if t.ID == msg.TablonID {
                tablonExists = true
                // Opcional: Actualizar nombre/geo si cambió?
                // t.Name = msg.Content.Title (si Title representa el nombre)
                break
            }
        }
        if !tablonExists && msg.TablonID != "" {
            newTablon := Tablon{
                ID:       msg.TablonID,
                Name:     msg.Content.Title, // Asume que Title es el nombre
                Messages: []Message{},
                // Geo: msg.Geo, // Añadir si se envía Geo en el mensaje P2P
            }
            tablones = append(tablones, newTablon)
            log.Printf(Green+"P2P: New tablon created locally: %s (ID: %s)"+Reset, newTablon.Name, newTablon.ID)
        }

	case "create": // Crear un mensaje dentro de un tablón
		foundTablon := false
		for i := range tablones {
			if tablones[i].ID == msg.TablonID {
                foundTablon = true
                // Evitar duplicados
                messageExists := false
                for _, existingMsg := range tablones[i].Messages {
                    if existingMsg.ID == msg.ID {
                        messageExists = true
                        break
                    }
                }
                if !messageExists {
                    tablones[i].Messages = append(tablones[i].Messages, msg)
                    log.Printf(Green+"P2P: New message (ID: %s) added to tablon %s"+Reset, msg.ID, msg.TablonID)
                }
				break
			}
		}
        if !foundTablon {
             log.Printf(Yellow+"P2P: Received message for non-existent tablon %s"+Reset, msg.TablonID)
        }

	case "delete_tablon":
        originalLength := len(tablones)
        filteredTablones := []Tablon{}
        for _, tablon := range tablones {
            if tablon.ID != msg.TablonID {
                filteredTablones = append(filteredTablones, tablon)
            }
        }
        if len(filteredTablones) < originalLength {
            tablones = filteredTablones
            log.Printf(Green+"P2P: Tablon deleted locally: %s"+Reset, msg.TablonID)
        }

	case "delete": // Eliminar un mensaje específico
		for i := range tablones {
			if tablones[i].ID == msg.TablonID {
                originalMsgCount := len(tablones[i].Messages)
                filteredMessages := []Message{}
                for _, message := range tablones[i].Messages {
                    if message.ID != msg.ID { // msg.ID aquí es el ID del mensaje a borrar
                       filteredMessages = append(filteredMessages, message)
                    }
                }
                if len(filteredMessages) < originalMsgCount {
                    tablones[i].Messages = filteredMessages
                    log.Printf(Green+"P2P: Message deleted locally (ID: %s) from tablon %s"+Reset, msg.ID, msg.TablonID)
                }
				break // Asumimos IDs de tablón únicos
			}
		}

	case "like":
        foundMessage := false
		for i := range tablones {
			if tablones[i].ID == msg.TablonID {
				for j := range tablones[i].Messages {
                    // msg.ID aquí es el ID del mensaje que recibió el like
					if tablones[i].Messages[j].ID == msg.ID {
                        // Simplemente actualizar al valor recibido. Podría causar inconsistencias
                        // si los mensajes llegan fuera de orden, pero es más simple.
                        // Para consistencia fuerte se necesitaría CRDTs o lógica más compleja.
                        if msg.Content.Likes != tablones[i].Messages[j].Content.Likes {
                            tablones[i].Messages[j].Content.Likes = msg.Content.Likes
                            log.Printf(Green+"P2P: Likes updated for message %s in tablon %s to %d"+Reset, msg.ID, msg.TablonID, msg.Content.Likes)
                        }
                        foundMessage = true
						break // Mensaje encontrado
					}
				}
                if foundMessage { break } // Tablón encontrado y mensaje procesado (o no encontrado)
			}
		}
         if !foundMessage {
             log.Printf(Yellow+"P2P: Received 'like' for non-existent message %s or tablon %s"+Reset, msg.ID, msg.TablonID)
        }


    case "binary_transfer":
        log.Printf(Green+"P2P: Received binary transfer announcement: %s (ID: %s) from %s"+Reset, msg.FileName, msg.ID, msg.From.Username)
        // Directorio para guardar archivos recibidos
        receivedDir := "received_files"
        if err := os.MkdirAll(receivedDir, 0755); err != nil {
            log.Printf(Red+"P2P: Error creating directory for received files '%s': %v"+Reset, receivedDir, err)
            return // No se puede guardar
        }
        // Sanear nombre de archivo y crear path de salida
        safeFileName := filepath.Base(msg.FileName) // Previene path traversal
        if safeFileName == "." || safeFileName == "/" || safeFileName == "" { safeFileName = "downloaded_file" } // Evitar nombres vacíos o peligrosos
         // Crear un nombre más único usando PeerID y MsgID (cortados para brevedad)
        peerIdPrefix := "unknown"
        if len(msg.From.PeerID) >= 8 { peerIdPrefix = msg.From.PeerID[:8] }
        msgIdPrefix := "unknown"
        if len(msg.ID) >= 8 { msgIdPrefix = msg.ID[:8] }
        outputPath := filepath.Join(receivedDir, fmt.Sprintf("%s_%s_%s", peerIdPrefix, msgIdPrefix, safeFileName))

        // Decodificar y guardar
        err := decodeBase64ToFile(msg.BinaryData, outputPath)
        if err != nil {
            log.Printf(Red+"P2P: Error saving received file '%s' to '%s': %v"+Reset, msg.FileName, outputPath, err)
        } else {
            log.Printf(Green+"P2P: File '%s' saved successfully to: %s"+Reset, msg.FileName, outputPath)
            // Opcional: Enviar notificación local, etc.
        }

	default:
		log.Printf(Yellow+"P2P: Received unhandled message action: '%s'"+Reset, msg.Action)
	}
}


// --- Cryptography & Serialization ---

// encryptMessage encripta un mensaje usando AES-GCM con una clave dada
func encryptMessage(plaintext, key []byte) ([]byte, error) {
    if len(key) != 32 {
        return nil, fmt.Errorf("invalid key size: expected 32 bytes for AES-256, got %d", len(key))
    }
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %w", err)
	}

	// Nunca usar el mismo nonce con la misma clave
	nonce := make([]byte, 12) // AES-GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM cipher: %w", err)
	}

	// Seal cifra y autentica. El nonce se prepende al ciphertext.
	// Seal appends the ciphertext to the first argument and returns the updated slice.
    // If the first argument is nil, a new slice is allocated.
    // Seal prepends the nonce to the returned ciphertext.
	ciphertext := aesgcm.Seal(nonce[:0], nonce, plaintext, nil) // Prepend nonce to ciphertext

	return ciphertext, nil
}

// decryptMessage desencripta un mensaje AES-GCM usando una clave dada
func decryptMessage(ciphertextWithNonce, key []byte) ([]byte, error) {
     if len(key) != 32 {
        return nil, fmt.Errorf("invalid key size: expected 32 bytes for AES-256, got %d", len(key))
    }
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %w", err)
	}

	nonceSize := 12 // AES-GCM standard nonce size
	if len(ciphertextWithNonce) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short (length %d, expected at least %d for nonce)", len(ciphertextWithNonce), nonceSize)
	}

	// Extraer nonce y ciphertext real
	nonce := ciphertextWithNonce[:nonceSize]
	ciphertext := ciphertextWithNonce[nonceSize:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM cipher: %w", err)
	}

	// Open descifra y verifica la autenticidad
    // Open appends the decrypted plaintext to the first argument and returns the updated slice.
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Este error es común si la clave es incorrecta o el mensaje fue manipulado
		return nil, fmt.Errorf("error opening GCM ciphertext (wrong key or corrupted data?): %w", err)
	}

	return plaintext, nil
}

// compress comprime datos usando Gzip
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	// Usar compresión con mejor relación velocidad/tamaño
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
    if err != nil {
        return nil, fmt.Errorf("gzip writer creation error: %w", err)
    }
	_, err = writer.Write(data)
	if err != nil {
        writer.Close() // Intentar cerrar incluso si hay error de escritura
		return nil, fmt.Errorf("gzip write error: %w", err)
	}
	err = writer.Close() // Es crucial cerrar para volcar los datos restantes
	if err != nil {
		return nil, fmt.Errorf("gzip close error: %w", err)
	}
	return buf.Bytes(), nil
}

// decompress descomprime datos Gzip
func decompress(data []byte) ([]byte, error) {
    if len(data) == 0 {
        return []byte{}, nil // Devolver vacío si la entrada es vacía
    }
	reader, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
        // Puede ocurrir si los datos no son gzip válido
		return nil, fmt.Errorf("gzip reader creation error: %w", err)
	}
	defer reader.Close()

	// Leer todo el contenido descomprimido
    decompressedData, err := ioutil.ReadAll(reader)
    if err != nil {
        // Puede ocurrir si el contenido gzip está corrupto
        return nil, fmt.Errorf("gzip read error: %w", err)
    }

	return decompressedData, nil
}

// mixnetEncrypt aplica múltiples capas de encriptación (si hay múltiples claves)
// NOTA: Con una sola clave (p2pKeys), esto es solo una encriptación simple.
func mixnetEncrypt(message []byte, keys [][]byte) ([]byte, error) {
	if len(keys) == 0 {
        log.Println(Yellow + "Warning: mixnetEncrypt called with no keys. Message not encrypted." + Reset)
		return message, nil // No encriptar si no hay claves
	}
	ciphertext := message
	// Encriptar capa por capa
	for i, key := range keys {
		var err error
		ciphertext, err = encryptMessage(ciphertext, key)
		if err != nil {
			return nil, fmt.Errorf("mixnet encryption layer %d failed: %w", i, err)
		}
	}
	return ciphertext, nil
}

// mixnetDecrypt desencripta múltiples capas en orden inverso
func mixnetDecrypt(ciphertext []byte, keys [][]byte) ([]byte, error) {
	if len(keys) == 0 {
         log.Println(Yellow + "Warning: mixnetDecrypt called with no keys. Assuming message was not encrypted." + Reset)
		return ciphertext, nil // No desencriptar si no había claves
	}
	plaintext := ciphertext
	// Desencriptar capa por capa, en orden inverso a la encriptación
	for i := len(keys) - 1; i >= 0; i-- {
		var err error
		plaintext, err = decryptMessage(plaintext, keys[i])
		if err != nil {
			// Si falla una capa, el mensaje completo es inválido
			return nil, fmt.Errorf("mixnet decryption layer %d failed: %w", i, err)
		}
	}
	return plaintext, nil
}

// serializeAndEncryptMessage: JSON -> Compress -> Encrypt (Mixnet)
func serializeAndEncryptMessage(msg Message, keys [][]byte) ([]byte, error) {
	// 1. Marshal a JSON
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("json marshal failed: %w", err)
	}

	// 2. Comprimir
	compressedData, err := compress(msgBytes)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}
    // log.Printf("Original: %d bytes, Compressed: %d bytes", len(msgBytes), len(compressedData))


	// 3. Encriptar (con las claves P2P proporcionadas)
	encryptedData, err := mixnetEncrypt(compressedData, keys)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}
    // if len(keys) > 0 { log.Printf("Encrypted size: %d bytes", len(encryptedData)) }


	return encryptedData, nil
}

// decryptAndDeserializeMessage: Decrypt (Mixnet) -> Decompress -> JSON Unmarshal
func decryptAndDeserializeMessage(data []byte, keys [][]byte) (Message, error) {
	var msg Message

	// 1. Desencriptar (con las claves P2P)
	decryptedData, err := mixnetDecrypt(data, keys)
	if err != nil {
		return msg, fmt.Errorf("decryption failed: %w", err)
	}
     // if len(keys) > 0 { log.Printf("Decrypted size: %d bytes", len(decryptedData)) }


	// 2. Descomprimir
	decompressedData, err := decompress(decryptedData)
	if err != nil {
		return msg, fmt.Errorf("decompression failed: %w", err)
	}
    // log.Printf("Decompressed size: %d bytes", len(decompressedData))


    // Log de datos descomprimidos (para depuración, ¡cuidado con datos binarios!)
    // if len(decompressedData) < 500 { // Log solo si es pequeño
    //    log.Printf("Decompressed data: %s", string(decompressedData))
    // }


	// 3. Unmarshal JSON
	err = json.Unmarshal(decompressedData, &msg)
	if err != nil {
		return msg, fmt.Errorf("json unmarshal failed: %w (data: %s)", err, string(decompressedData))
	}

	return msg, nil
}


// --- Libp2p Setup & Discovery ---

// setupMDNS inicializa el descubrimiento de pares locales mediante mDNS
func setupMDNS(ctx context.Context, h host.Host, serviceTag string) error {
    if serviceTag == "" {
        log.Println(Yellow + "mDNS service tag is empty, using default." + Reset)
        serviceTag = "_libp2p-discovery._tcp" // Un tag por defecto razonable
    }
	// Usar un Notifee para manejar peers encontrados
	service := mdns.NewMdnsService(h, serviceTag, &mdnsNotifee{h: h})
	return service.Start()
}

// mdnsNotifee implementa la interfaz para ser notificado de peers mDNS
type mdnsNotifee struct {
	h host.Host // Referencia al host local
}

// HandlePeerFound se llama cuando mDNS descubre un nuevo par
func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	// No conectarse a uno mismo
	if pi.ID == n.h.ID() {
		return
	}
	// Filtrar direcciones no útiles (ej: loopback si no se espera conexión local)
    // Podríamos añadir más lógica de filtrado si fuera necesario
	log.Printf(Blue+"mDNS Peer Found: %s. Addresses: %v. Connecting..."+Reset, pi.ID.ShortString(), pi.Addrs)

    // Intentar conectar en segundo plano
    go func() {
        ctxConnect, cancel := context.WithTimeout(context.Background(), 20*time.Second) // Aumentar timeout
        defer cancel()
        if err := n.h.Connect(ctxConnect, pi); err != nil {
             // Loguear el error detallado de conexión mDNS
            log.Printf(Yellow+"mDNS connection failed to %s: %v"+Reset, pi.ID.ShortString(), err)
        } else {
            log.Printf(Green+"mDNS connection successful to: %s"+Reset, pi.ID.ShortString())
        }
    }()
}

// hashTopic crea un hash SHA-256 del nombre del topic para usarlo en DHT/PubSub
// Esto ayuda a ofuscar el nombre real del topic en la red pública DHT.
func hashTopic(topic string) string {
	hash := sha256.Sum256([]byte(topic))
	return hex.EncodeToString(hash[:]) // Devuelve el hash como string hexadecimal
}

// initDHT inicializa y arranca la Kademlia DHT para descubrimiento de pares
func initDHT(ctx context.Context, h host.Host) (*dht.IpfsDHT, error) {
    // Opciones para el DHT
    opts := []dht.Option{
        dht.Mode(dht.ModeAutoServer), // Intentar ser servidor DHT si es posible (ModeAuto es más conservador)
        dht.ProtocolPrefix("/myapp-p2p"), // Usar un prefijo de protocolo único
         // Podrías añadir peers bootstrap específicos de tu red aquí si los tienes
        // dht.BootstrapPeers(peerAddrInfo1, peerAddrInfo2),
    }

	log.Println(Blue + "Creating new DHT..." + Reset)
	kademliaDHT, err := dht.New(ctx, h, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}
    log.Println(Green + "DHT instance created." + Reset)


	// Arrancar la DHT (conectar a nodos bootstrap por defecto de libp2p)
    log.Println(Blue + "Bootstrapping DHT..." + Reset)
	if err = kademliaDHT.Bootstrap(ctx); err != nil {
         // No fatal, podría conectarse más tarde, pero loguear como error
		log.Printf(Red+"ERROR: Failed to bootstrap DHT: %v. Discovery might be delayed."+Reset, err)
        // return nil, fmt.Errorf("failed to bootstrap DHT: %w", err) // O hacerlo fatal
	} else {
         log.Println(Green + "DHT bootstrap process initiated." + Reset)
    }


	// Conectar explícitamente a algunos peers bootstrap para asegurar conectividad inicial
	// Esto es útil si el bootstrap automático no funciona bien inmediatamente.
	var wg sync.WaitGroup
	connectedBootstrappers := 0
    log.Println(Blue + "Attempting connections to default bootstrap peers..." + Reset)
	for _, peerAddr := range dht.DefaultBootstrapPeers {
		peerinfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
		if err != nil {
			log.Printf(Yellow+"DHT: Error parsing bootstrap peer address %s: %v"+Reset, peerAddr.String(), err)
			continue
		}
		wg.Add(1)
		go func(pi peer.AddrInfo) {
			defer wg.Done()
            // Usar un contexto con timeout más corto para estas conexiones iniciales
            ctxConnect, cancel := context.WithTimeout(ctx, 10*time.Second)
            defer cancel()
			if err := h.Connect(ctxConnect, pi); err != nil {
				// Loguear como debug o warning, no es necesariamente un error fatal
				// log.Printf(Yellow+"DHT Bootstrap warning (could not connect to %s): %v"+Reset, pi.ID.ShortString(), err)
			} else {
				log.Printf(Blue+"DHT Bootstrap connection successful to: %s"+Reset, pi.ID.ShortString())
                // Usar sync.Mutex si modificáramos una variable compartida aquí,
                // pero para el log no es estrictamente necesario.
				connectedBootstrappers++ // Cuidado: concurrencia si no se usa Atomic o Mutex. Mejor contar al final.
			}
		}(*peerinfo)
	}
	wg.Wait() // Esperar a que terminen los intentos de conexión

    // Re-evaluar la cuenta de conectados de forma segura después del Wait()
    finalConnectedCount := 0
    for _, peerAddr := range dht.DefaultBootstrapPeers {
        peerinfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
        if err == nil && h.Network().Connectedness(peerinfo.ID) == network.Connected {
            finalConnectedCount++
        }
    }


    if finalConnectedCount == 0 {
        log.Println(Yellow + "DHT: Warning - Could not connect to any default bootstrap peers initially." + Reset)
    } else {
        log.Printf(Green + "DHT: Connected to %d default bootstrap peers." + Reset, finalConnectedCount)
    }

	return kademliaDHT, nil
}

// discoverPeers usa DHT para anunciar la presencia en un topic y encontrar otros pares
func discoverPeers(ctx context.Context, h host.Host, topicName string) {
    log.Printf(Blue+"Initializing DHT for peer discovery (Topic: %s)..."+Reset, topicName)
	kademliaDHT, err := initDHT(ctx, h)
	if err != nil {
        // Si DHT falla, el descubrimiento global no funcionará. mDNS podría seguir funcionando.
        log.Printf(Red+"ERROR: Could not initialize DHT: %v. Global peer discovery might fail."+Reset, err)
        // Continuar para permitir que mDNS funcione si está habilitado
    } else {
        log.Println(Green + "DHT Initialized successfully for discovery." + Reset)
         // Usar Routing Discovery sobre la DHT solo si la DHT se inicializó
        routingDiscovery := drouting.NewRoutingDiscovery(kademliaDHT)

        // Anunciar que este nodo está interesado en el topic (usa el hash)
        hashedTopic := hashTopic(topicName)
        log.Printf(Blue+"Announcing presence for topic '%s' (Hashed: %s) on the DHT..."+Reset, topicName, hashedTopic)
        dutil.Advertise(ctx, routingDiscovery, hashedTopic)
        log.Println(Green + "DHT Advertisement started." + Reset)


        // Bucle para buscar pares periódicamente
        ticker := time.NewTicker(1 * time.Minute) // Buscar nuevos pares cada minuto
        defer ticker.Stop()

        findAndConnect := func() {
            log.Println(Blue + "Searching for peers for topic via DHT..." + Reset)
            // Usar FindPeers con un contexto propio para la búsqueda
            findCtx, findCancel := context.WithTimeout(ctx, 30*time.Second)
            defer findCancel()
            peerChan, err := routingDiscovery.FindPeers(findCtx, hashedTopic)
            if err != nil {
                // No fatal, puede ocurrir si la red está inestable
                log.Printf(Yellow+"DHT FindPeers warning for topic '%s': %v"+Reset, topicName, err)
                return // Error al buscar, reintentar en el próximo tick
            }

            foundPeers := 0
            connectionAttempts := 0
            // Iterar sobre los peers encontrados
            for peerInfo := range peerChan {
                // Ignorar a sí mismo
                if peerInfo.ID == h.ID() {
                    continue
                }

                foundPeers++
                // Intentar conectar si no estamos ya conectados
                if h.Network().Connectedness(peerInfo.ID) != network.Connected {
                     log.Printf(Blue+"DHT Found peer: %s. Attempting connection..."+Reset, peerInfo.ID.ShortString())
                     connectionAttempts++
                     go func(pi peer.AddrInfo) { // Conectar en goroutine para no bloquear la búsqueda
                         ctxConnect, cancel := context.WithTimeout(ctx, 20*time.Second)
                         defer cancel()
                         if err := h.Connect(ctxConnect, pi); err != nil {
                            // Loguear como debug o info, no warning necesariamente
                            // log.Printf(Blue+"DHT Failed connecting to %s: %v"+Reset, pi.ID.ShortString(), err)
                         } else {
                             log.Printf(Green+"DHT Connection successful to discovered peer: %s"+Reset, pi.ID.ShortString())
                         }
                     }(peerInfo)
                }
                 // else { log.Printf("DHT Found peer %s (already connected)", peerInfo.ID.ShortString()) }
            }
             if foundPeers > 0 {
                 log.Printf(Green+"DHT Peer search cycle complete. Found %d potential peers, attempted %d new connections."+Reset, foundPeers, connectionAttempts)
             } else {
                 log.Println(Blue+"DHT Peer search cycle complete. No new peers found in this cycle."+Reset)
             }
        }

        // Búsqueda inicial después de un breve retraso para permitir que DHT se estabilice un poco
        time.Sleep(5 * time.Second)
        findAndConnect()

        // Búsquedas periódicas
        for {
            select {
            case <-ticker.C:
                findAndConnect()
            case <-ctx.Done():
                log.Println(Yellow + "Peer discovery context canceled. Stopping DHT discovery loop." + Reset)
                return
            }
        }
    } // Fin del else (DHT inicializado)

}

// --- Main Function ---

func main() {
	flag.Parse() // Parsear flags de línea de comando (aunque ahora se prefiere config.yaml)

	// --- 1. Leer Configuración ---
	config, err := readConfig()
	if err != nil {
		log.Fatalf(Red+"Failed to read or validate config.yaml: %v"+Reset, err)
	}
    // Asignar TopicName de config si existe, si no, usar el flag (deprecado)
    if config.TopicName == "" {
        config.TopicName = *topicNameFlag
        log.Printf(Yellow + "Warning: topicName not found in config.yaml, using flag value: %s" + Reset, config.TopicName)
    }
    if config.TopicName == "" {
         log.Fatalf(Red+"Error: Topic name is empty. Please set topicName in config.yaml or via flag."+Reset)
    }


	// --- 2. Configurar Router HTTP y Rutas ---
	r := mux.NewRouter()
	api := r.PathPrefix("/api").Subrouter()

	// Rutas de la API (prefijo /api ya aplicado)
	api.HandleFunc("/createTablon", createTablonHandler).Methods("POST")
	api.HandleFunc("/readTablon", readTablonHandler).Methods("GET")     // GET /api/readTablon?id=... o GET /api/readTablon
	api.HandleFunc("/deleteTablon", deleteTablonHandler).Methods("DELETE") // DELETE /api/deleteTablon?id=...
	api.HandleFunc("/addMessage", addMessageToTablonHandler).Methods("POST") // POST /api/addMessage?tablon_id=...&message=...
	api.HandleFunc("/deleteMessage", deleteMessageHandler).Methods("DELETE") // DELETE /api/deleteMessage?tablonId=...&messageId=...
	api.HandleFunc("/likeMessage", likeMessageHandler).Methods("POST")   // POST /api/likeMessage?tablonId=...&messageId=...
    api.HandleFunc("/sendBinary", sendBinaryHandler).Methods("POST")     // POST /api/sendBinary (con form-data)

	// Rutas de autenticación
	api.HandleFunc("/login", generateTokenHandler).Methods("POST") // POST /api/login

	// Rutas deprecadas (mantener opcionalmente)
	api.HandleFunc("/send", sendMessageHandler).Methods("POST")
	api.HandleFunc("/recibe", receiveMessagesHandler).Methods("GET")
    // api.HandleFunc("/generateToken", generateTokenHandler).Methods("GET") // GET para generar token es inseguro, eliminar o cambiar a POST


	// --- 3. Configurar Middleware ---
	// Middleware CORS (permitir orígenes según sea necesario)
	corsMiddleware := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}), // ¡CONFIGURAR ESTO PARA PRODUCCIÓN! Ej: []string{"https://sudominio.com"}
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "X-Requested-With"}),
		handlers.AllowCredentials(), // Si necesitas cookies o auth headers
	)

	// Middleware de Cabeceras de Seguridad
	securityMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Frame-Options", "DENY") // Previene clickjacking
			w.Header().Set("X-XSS-Protection", "1; mode=block") // Activa protección XSS del navegador
			w.Header().Set("X-Content-Type-Options", "nosniff") // Evita que el navegador adivine el MIME type
            w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin") // Controla info enviada en Referer
            // Content-Security-Policy es potente pero compleja de configurar:
            // w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';")
			// Solo añadir HSTS si se está usando SSL/TLS
            if config.UseSSL {
                w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            }
			next.ServeHTTP(w, r)
		})
	}

	// Aplicar middleware: seguridad -> CORS -> router
	finalHandler := securityMiddleware(corsMiddleware(r))

	// --- 4. Servir Archivos Estáticos ---
	// Sirve archivos desde el directorio './web' si la ruta no coincide con /api/
	fs := http.FileServer(http.Dir("./web"))
	r.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Si la ruta empieza con /api/, el router 'api' ya la manejó.
		// Si no, intentamos servir un archivo estático.
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			// Servir index.html para rutas no encontradas (típico en SPAs)
            // Comprobar si el archivo existe
            staticFilePath := filepath.Join("./web", filepath.Clean(r.URL.Path))
            _, err := os.Stat(staticFilePath)
            if os.IsNotExist(err) && !strings.HasSuffix(r.URL.Path, "/") && filepath.Ext(r.URL.Path) == "" {
                 // Si no existe y parece una ruta de SPA (sin extensión), servir index.html
                 http.ServeFile(w, r, filepath.Join("./web", "index.html"))
                 return
            }
            // Si existe o es una ruta base "/", dejar que FileServer lo maneje
			fs.ServeHTTP(w, r)
		}
		// Si es /api/, Mux se encarga, no hacemos nada aquí (ya fue manejado por el router principal 'r').
	}))


	// --- 5. Iniciar Servidor HTTP/HTTPS ---
	serverAddress := config.WebServerAddr // Dirección del config (ej: ":8080" o ":8443")

	go func() {
		if config.UseSSL {
			// --- Iniciar Servidor HTTPS ---
			certFile := config.CertFile // Path desde config o por defecto
			keyFile := config.KeyFile   // Path desde config o por defecto

			log.Printf(Green+"Attempting to start HTTPS server on %s using cert=%s, key=%s"+Reset, serverAddress, certFile, keyFile)

			// Comprobar existencia de archivos
			if _, err := os.Stat(certFile); os.IsNotExist(err) {
				log.Fatalf(Red+"FATAL: Certificate file not found at '%s'. Cannot start HTTPS server."+Reset, certFile)
			}
			if _, err := os.Stat(keyFile); os.IsNotExist(err) {
				log.Fatalf(Red+"FATAL: Key file not found at '%s'. Cannot start HTTPS server."+Reset, keyFile)
			}

			log.Println(Green + "Starting HTTPS server..." + Reset)
			err := http.ListenAndServeTLS(serverAddress, certFile, keyFile, finalHandler)
			if err != nil {
				log.Fatalf(Red+"FATAL: HTTPS server error: %v"+Reset, err)
			}
		} else {
			// --- Iniciar Servidor HTTP ---
			log.Printf(Yellow+"Starting HTTP server on %s (SSL disabled in config)"+Reset, serverAddress)
			err := http.ListenAndServe(serverAddress, finalHandler)
			if err != nil {
				log.Fatalf(Red+"FATAL: HTTP server error: %v"+Reset, err)
			}
		}
	}()


	// --- 6. Configurar Libp2p Host ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Asegura que el contexto se cancele al salir de main

	// Opciones para el host libp2p - *** CONFIGURACIÓN EXPLÍCITA ***
	log.Println(Blue + "Configuring P2P host with explicit TCP transport and TLS security..." + Reset)
	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(config.ListenAddress), // Dirección P2P del config

		// --- Configuración Explícita de Transporte y Seguridad ---
		libp2p.Transport(libp2ptcp.NewTCPTransport), // Forzar solo transporte TCP
		libp2p.Security(libp2ptls.ID, libp2ptls.New), // Forzar solo seguridad TLS (ID: "/tls/1.0.0")
		// No usar libp2p.DefaultSecurity

		// --- Mantener otras opciones útiles (pueden comentarse si causan problemas) ---
		libp2p.NATPortMap(),            // Intentar mapeo UPnP/NAT-PMP
		libp2p.EnableRelay(),           // Habilitar soporte para relays (cliente y servidor)
		libp2p.EnableHolePunching(),    // Habilitar perforación de NAT
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		log.Fatalf(Red+"FATAL: Failed to create P2P host: %v"+Reset, err)
	}
	log.Printf(Green+"P2P Host created successfully!"+Reset)
	log.Printf(Blue+"  - Host ID: %s"+Reset, h.ID().String())
	log.Printf(Blue+"  - Listening on: %v"+Reset, h.Addrs())

	// --- 7. Configurar Descubrimiento P2P (mDNS y DHT) ---
	// mDNS (descubrimiento local)
	if config.Mdns.Enabled {
		log.Println(Blue + "Setting up mDNS discovery..." + Reset)
		if err := setupMDNS(ctx, h, config.Mdns.ServiceTag); err != nil {
			// No fatal, DHT podría funcionar
			log.Printf(Yellow+"Warning: Failed to setup mDNS: %v. Continuing without it..."+Reset, err)
		} else {
			log.Printf(Green+"mDNS Discovery enabled with service tag: '%s'"+Reset, config.Mdns.ServiceTag)
		}
	} else {
        log.Println(Yellow + "mDNS discovery is disabled in config." + Reset)
    }

	// DHT (descubrimiento global) - Iniciar en goroutine
	go discoverPeers(ctx, h, config.TopicName)


	// --- 8. Configurar PubSub ---
	log.Println(Blue + "Setting up P2P PubSub..." + Reset)
	ps, err := pubsub.NewGossipSub(ctx, h,
        pubsub.WithMaxMessageSize(config.MaxMessageSize),
        // pubsub.WithFloodPublish(true), // Considerar si se necesita publicación más rápida a costa de más tráfico
        // pubsub.WithMessageSigning(true), // Firmar mensajes (requiere claves privadas)
        // pubsub.WithStrictSignatureVerification(true),
    )
	if err != nil {
		log.Fatalf(Red+"FATAL: Failed to create PubSub instance: %v"+Reset, err)
	}

	// Unirse al topic (usando el hash del nombre)
    hashedTopic := hashTopic(config.TopicName)
	p2pTopic, err = ps.Join(hashedTopic)
	if err != nil {
		log.Fatalf(Red+"FATAL: Failed to join P2P topic '%s' (Hashed: %s): %v"+Reset, config.TopicName, hashedTopic, err)
	}
	log.Printf(Green+"Successfully joined P2P topic: '%s' (Hashed: %s)"+Reset, config.TopicName, hashedTopic)

	// Suscribirse al topic para recibir mensajes
	p2pSub, err = p2pTopic.Subscribe()
	if err != nil {
		log.Fatalf(Red+"FATAL: Failed to subscribe to P2P topic: %v"+Reset, err)
	}
	log.Println(Green + "Successfully subscribed to P2P topic." + Reset)

	// Iniciar el manejador de mensajes P2P en una goroutine
	go handleP2PMessages(ctx)


	// --- 9. Mantener la aplicación corriendo ---
	log.Println(Green + "Application started successfully. Waiting for connections and messages...")
	log.Println(Blue + "Press Ctrl+C to exit." + Reset)
	// Bloquear indefinidamente hasta que se reciba una señal de interrupción (como Ctrl+C)
	// O hasta que el contexto sea cancelado
	select {
        case <-ctx.Done():
            log.Println(Yellow + "Main context canceled. Shutting down..." + Reset)
        // Podríamos añadir manejo de señales OS aquí (SIGINT, SIGTERM)
        // sigs := make(chan os.Signal, 1)
        // signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
        // <-sigs
        // log.Println(Yellow + "Received OS signal. Shutting down..." + Reset)
        // cancel() // Cancelar el contexto si recibimos señal
    }

    // --- 10. Limpieza (Opcional pero recomendado) ---
    log.Println(Yellow + "Performing cleanup..." + Reset)
    // Cerrar suscripción y topic
    if p2pSub != nil {
        p2pSub.Cancel()
        log.Println(Blue + "P2P subscription canceled." + Reset)
    }
    if p2pTopic != nil {
        // Cerrar el topic puede tardar un poco si hay mensajes pendientes
        if err := p2pTopic.Close(); err != nil {
             log.Printf(Red+"Error closing P2P topic: %v"+Reset, err)
        } else {
             log.Println(Blue + "P2P topic closed." + Reset)
        }
    }
    // Cerrar el host libp2p
    log.Println(Blue + "Closing P2P host..." + Reset)
    if err := h.Close(); err != nil {
        log.Printf(Red+"Error closing P2P host: %v"+Reset, err)
    } else {
        log.Println(Blue + "P2P host closed." + Reset)
    }
    log.Println(Green + "Shutdown complete." + Reset)

}

// --- Funciones Auxiliares Adicionales (Opcional) ---

// executeSystemCommand (ya presente, revisar si se usa)
func executeSystemCommand(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing command '%s %s': %v, stderr: %s", command, strings.Join(args," "), err, stderr.String())
	}
	return out.String(), nil
}

// generateRandomInt (ya presente, revisar si se usa)
func generateRandomInt(max int) (int, error) {
    if max <= 0 {
        return 0, fmt.Errorf("max must be positive")
    }
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

// routeMessage (ya presente, parece una simulación de retraso, revisar si se usa)
func routeMessage(data []byte) ([]byte, error) {
	delay, err := generateRandomInt(1000) // Retraso aleatorio hasta 1000ms
	if err != nil {
		return nil, err
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
	return data, nil
}


// --- Estructuras y funciones P2P obsoletas o no usadas (revisar y eliminar si no son necesarias) ---

// streamConsoleTo (parece para entrada de consola, ¿se usa?)
func streamConsoleTo(ctx context.Context, topic *pubsub.Topic, keys [][]byte, retryInterval int, from string, to string) {
	// ... (código original)
    log.Println(Yellow+"Warning: streamConsoleTo function called - is console input needed?"+Reset)
    reader := bufio.NewReader(os.Stdin)
	maxRetries := 5
	for {
		s, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF || ctx.Err() != nil {
                log.Println(Blue+"Exiting streamConsoleTo due to EOF or context cancellation."+Reset)
				break
			}
			log.Printf(Red+"Failed to read input in streamConsoleTo: %v"+Reset, err)
            break // Salir en caso de error de lectura
		}
		s = strings.TrimSpace(s)
        if s == "" { continue } // Ignorar líneas vacías

		msg := Message{
			ID:        generateMessageID(),
			From:      UserInfo{PeerID: from, Username: "ConsoleUser", Photo: ""}, // Usar info real si es posible
			To:        to, // "BROADCAST" o específico
			Timestamp: time.Now().Format(time.RFC3339),
			Content: Content{
				Title:      "Console Message",
				Message:    s,
			},
            Action: "console_input", // Acción específica
		}
		serializedMsg, err := serializeAndEncryptMessage(msg, keys)
		if err != nil {
			log.Printf(Red+"Failed to serialize message from console: %v"+Reset, err)
			continue
		}

        publishSuccessful := false
		for i := 0; i < maxRetries; i++ {
            pubCtx, pubCancel := context.WithTimeout(ctx, 10*time.Second)
			if err := topic.Publish(pubCtx, serializedMsg); err != nil {
				pubCancel()
                log.Printf(Red+"Console publish error: %v, retrying... (%d/%d)"+Reset, err, i+1, maxRetries)
                // Verificar si el contexto principal fue cancelado
                if ctx.Err() != nil { break }
				time.Sleep(time.Duration(retryInterval) * time.Millisecond * time.Duration(1<<i)) // Exponencial backoff
			} else {
                pubCancel()
                publishSuccessful = true
				break
			}
		}
        if !publishSuccessful {
            log.Printf(Red+"Failed to publish console message after %d retries."+Reset, maxRetries)
            if ctx.Err() != nil { break } // Salir si el contexto fue cancelado
        }
	}
}

// printMessagesFrom (lógica de impresión simple, reemplazada por handleP2PMessages y processP2PMessage)
func printMessagesFrom(ctx context.Context, sub *pubsub.Subscription, keys [][]byte) {
	// ... (código original)
    log.Println(Yellow+"Warning: printMessagesFrom function called - likely deprecated by handleP2PMessages"+Reset)
	for {
		m, err := sub.Next(ctx)
		if err != nil {
            if ctx.Err() != nil {
                 log.Println(Blue+"Exiting printMessagesFrom due to context cancellation."+Reset)
                 return
            }
			log.Printf(Red+"Failed to get next message in printMessagesFrom: %v"+Reset, err)
            // Podría ser fatal o requerir re-suscripción
            return // Salir en caso de error
		}
		msg, err := decryptAndDeserializeMessage(m.Message.GetData(), keys)
		if err != nil {
			log.Printf(Red+"Deserialization error in printMessagesFrom: %v"+Reset, err)
			continue
		}

		// Log simple
		fmt.Printf("[PrintMsg] From: %s -> %s\n", msg.From.Username, msg.Content.Message)

	}
}