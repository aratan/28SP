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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"gopkg.in/yaml.v2"
)

var (
	topicNameFlag = flag.String("topicName", "applesauce", "name of topic to join")
	jwtSecretKey  = []byte("your-256-bit-secret")
)

var (
	p2pTopic     *pubsub.Topic
	p2pSub       *pubsub.Subscription
	p2pKeys      [][]byte
	p2pKeysMutex sync.Mutex // Mutex for safely updating encryption keys
)

const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Reset  = "\033[0m"
)

type Config struct {
	TopicName      string `yaml:"topicName"`
	EncryptionKey  string `yaml:"encryptionKey"`
	LogLevel       string `yaml:"logLevel"`
	ListenAddress  string `yaml:"listenAddress"`
	MaxMessageSize int    `yaml:"maxMessageSize"`
	LogFile        string `yaml:"logFile"`
	RetryInterval  int    `yaml:"retryInterval"`
	Mdns           struct {
		Enabled    bool   `yaml:"enabled"`
		ServiceTag string `yaml:"serviceTag"`
	} `yaml:"mdns"`
	UseSSL bool `yaml:"useSSL"`
	Users  []struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"users"`
}

type Message struct {
	ID         string   `json:"id"`
	From       UserInfo `json:"from"`
	To         string   `json:"to"`
	Timestamp  string   `json:"timestamp"`
	Content    Content  `json:"content"`
	Action     string   `json:"action"` // "create", "delete", "like"
	TablonID   string   `json:"tablonId"`
	BinaryData string   `json:"binaryData,omitempty"`
	FileName   string   `json:"fileName,omitempty"`
}

type Tablon struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Messages []Message `json:"messages"`
	Geo      string    `json:"geo"`
}

var tablones []Tablon
var tablonesMutex sync.Mutex

type UserInfo struct {
	PeerID   string `json:"peerId"`
	Username string `json:"username"`
	Photo    string `json:"photo"`
}

type Content struct {
	Title      string    `json:"title"`
	Message    string    `json:"message"`
	Subtitle   string    `json:"subtitle"`
	Likes      int       `json:"likes"`
	Comments   []Comment `json:"comments"`
	Subscribed bool      `json:"subscribed"`
}

type Comment struct {
	Username string `json:"username"`
	Comment  string `json:"comment"`
}

var receivedMessages []Message
var messagesMutex sync.Mutex

func readConfig() (*Config, error) {
	data, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// New function to encode file to base64
func encodeFileToBase64(filePath string) (string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// New function to decode base64 to file
func decodeBase64ToFile(base64String, outputPath string) error {
	data, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(outputPath, data, 0644)
}

// New handler for sending binary data
// New handler for sending binary data
func sendBinaryHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create a temporary file to store the uploaded content
	tempFile, err := ioutil.TempFile("", "upload-*.tmp")
	if err != nil {
		http.Error(w, "Error creating temporary file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Copy the uploaded file to the temporary file
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving the file", http.StatusInternalServerError)
		return
	}

	// Encode the file to base64
	base64Data, err := encodeFileToBase64(tempFile.Name())
	if err != nil {
		http.Error(w, "Error encoding file to base64", http.StatusInternalServerError)
		return
	}

	// Create a new message with the binary data
	msg := Message{
		ID:         generateMessageID(),
		From:       UserInfo{PeerID: "sender_peer_id", Username: "sender_username", Photo: "sender_photo_url"},
		To:         "BROADCAST", // or specific peer ID
		Timestamp:  time.Now().Format(time.RFC3339),
		Action:     "binary_transfer",
		BinaryData: base64Data,
		FileName:   header.Filename,
	}

	// Publish the message to the P2P network
	go publishToP2P(msg)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "file sent", "messageId": msg.ID})
}

// New handler for receiving binary data
func receiveBinaryHandler(w http.ResponseWriter, r *http.Request) {
	var msg Message
	err := json.NewDecoder(r.Body).Decode(&msg)
	if err != nil {
		http.Error(w, "Error decoding message", http.StatusBadRequest)
		return
	}

	if msg.Action != "binary_transfer" || msg.BinaryData == "" {
		http.Error(w, "Invalid binary transfer message", http.StatusBadRequest)
		return
	}

	// Create a directory for received files if it doesn't exist
	receivedDir := "received_files"
	if err := os.MkdirAll(receivedDir, 0755); err != nil {
		http.Error(w, "Error creating directory for received files", http.StatusInternalServerError)
		return
	}

	// Generate a unique filename
	outputPath := filepath.Join(receivedDir, fmt.Sprintf("%s_%s", msg.ID, msg.FileName))

	// Decode and save the file
	err = decodeBase64ToFile(msg.BinaryData, outputPath)
	if err != nil {
		http.Error(w, "Error saving received file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "file received", "filePath": outputPath})
}

// Actualiza createTablonHandler para publicar en la red P2P
func createTablonHandler(w http.ResponseWriter, r *http.Request) {
	// Verificar el token JWT
	if !verifyJWT(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// Obtener parámetros de la consulta
	tablonName := r.URL.Query().Get("name")
	if tablonName == "" {
		http.Error(w, "Missing 'name' query parameter", http.StatusBadRequest)
		return
	}

	mensaje := r.URL.Query().Get("mensaje")
	geo := r.URL.Query().Get("geo")

	// Obtener información del usuario del token JWT
	claims := getClaimsFromToken(r)
	userInfo := UserInfo{
		PeerID:   claims["peerId"].(string),
		Username: claims["username"].(string),
		Photo:    claims["photo"].(string),
	}
	// Crear el mensaje que se publicará
	msg := Message{
		ID:        generateMessageID(), // Asegúrate de que esta función esté definida para generar un ID único
		From:      userInfo,
		To:        "BROADCAST",
		Timestamp: time.Now().Format(time.RFC3339),
		Content:   Content{Title: tablonName, Message: mensaje, Subtitle: "Información del Tablón", Likes: 0, Comments: []Comment{}, Subscribed: false},
		Action:    "create",
		TablonID:  generateMessageID(), // Asegúrate de que esta función esté definida o usa un valor adecuado
	}

	// Publicar en la red P2P en una goroutine
	go publishToP2P(msg)

	// Crear el nuevo Tablón
	tablon := Tablon{
		ID:       generateMessageID(),
		Name:     tablonName,
		Messages: []Message{msg},
		Geo:      geo,
	}

	// Sincronizar acceso a la lista de Tablones
	tablonesMutex.Lock()
	tablones = append(tablones, tablon)
	tablonesMutex.Unlock()

	// Crear la respuesta
	response := map[string]string{
		"status":  "tablon created",
		"id":      tablon.ID,
		"name":    tablonName,
		"mensaje": mensaje,
		"geo":     geo,
	}

	// Establecer el encabezado de tipo de contenido y codificar la respuesta en JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func publishToP2P(msg Message) {
	// Lock the mutex to safely access the encryption keys
	p2pKeysMutex.Lock()
	keys := p2pKeys // Make a local copy of the keys
	p2pKeysMutex.Unlock()

	// Serialize the message with the current keys
	serializedMsg, err := serializeMessage(msg, keys)
	if err != nil {
		log.Printf(Red+"Failed to serialize message for P2P: %v"+Reset, err)
		return
	}

	// Publish the message to the P2P network
	err = p2pTopic.Publish(context.Background(), serializedMsg)
	if err != nil {
		log.Printf(Red+"Failed to publish message to P2P network: %v"+Reset, err)
	}
}

// Actualiza addMessageToTablonHandler para publicar en la red P2P
func addMessageToTablonHandler(w http.ResponseWriter, r *http.Request) {
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

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			msg := Message{
				ID:        generateMessageID(),
				From:      UserInfo{PeerID: "your_peer_id", Username: "your_username", Photo: "your_photo_url"},
				To:        "BROADCAST",
				Timestamp: time.Now().Format(time.RFC3339),
				Content:   Content{Title: tablon.Name, Message: messageContent, Subtitle: "Sistema", Likes: 0, Comments: []Comment{}, Subscribed: false},
				Action:    "create",
				TablonID:  tablonID,
			}

			tablones[i].Messages = append(tablones[i].Messages, msg)

			// Publicar en la red P2P
			go publishToP2P(msg)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "message added"})
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}

func readTablonHandler(w http.ResponseWriter, r *http.Request) {
	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tablones)
}
func validateCredentials(username, password string) bool {
	config, err := readConfig()
	if err != nil {
		log.Printf(Red+"Failed to read config: %v"+Reset, err)
		return false
	}

	for _, user := range config.Users {
		if user.Username == username && user.Password == password {
			return true
		}
	}
	return false
}
func getClaimsFromToken(r *http.Request) jwt.MapClaims {
	tokenString := r.Header.Get("Authorization")
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims
	}

	return nil
}
func deleteTablonHandler(w http.ResponseWriter, r *http.Request) {
	// Verificar el token JWT
	if !verifyJWT(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tablonID := r.URL.Query().Get("id")
	if tablonID == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	// Obtener información del usuario del token JWT
	claims := getClaimsFromToken(r)
	userInfo := UserInfo{
		PeerID:   claims["peerId"].(string),
		Username: claims["username"].(string),
		Photo:    claims["photo"].(string),
	}

	msg := Message{
		ID:        tablonID,
		From:      userInfo,
		To:        "BROADCAST",
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    "delete",
	}

	go publishToP2P(msg)

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			tablones = append(tablones[:i], tablones[i+1:]...)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "tablon deleted"})
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}
func verifyJWT(r *http.Request) bool {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return false
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		return false
	}

	return token.Valid
}
func deleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	// Verificar el token JWT
	if !verifyJWT(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tablonID := r.URL.Query().Get("tablonId")
	messageID := r.URL.Query().Get("messageId")
	msg := Message{
		ID:        messageID,
		From:      UserInfo{PeerID: "your_peer_id", Username: "your_username", Photo: "your_photo_url"},
		To:        "BROADCAST",
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    "delete",
		TablonID:  tablonID,
	}

	go publishToP2P(msg)

	if tablonID == "" || messageID == "" {
		http.Error(w, "Missing 'tablonId' or 'messageId' query parameter", http.StatusBadRequest)
		return
	}

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			for j, message := range tablon.Messages {
				if message.ID == messageID {
					tablones[i].Messages = append(tablon.Messages[:j], tablon.Messages[j+1:]...)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]string{"status": "message deleted"})
					return
				}
			}
			http.Error(w, "Message not found", http.StatusNotFound)
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}

func likeMessageHandler(w http.ResponseWriter, r *http.Request) {
	tablonID := r.URL.Query().Get("tablonId")
	messageID := r.URL.Query().Get("messageId")

	if tablonID == "" || messageID == "" {
		http.Error(w, "Missing 'tablonId' or 'messageId' query parameter", http.StatusBadRequest)
		return
	}

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	var updatedLikes int
	var messageFound bool

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			for j, message := range tablon.Messages {
				if message.ID == messageID {
					tablones[i].Messages[j].Content.Likes++
					updatedLikes = tablones[i].Messages[j].Content.Likes
					messageFound = true
					break
				}
			}
			if messageFound {
				break
			}
		}
	}

	if !messageFound {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}

	// Crear un mensaje P2P para propagar el like
	likeMsg := Message{
		ID:        generateMessageID(),
		From:      UserInfo{PeerID: "your_peer_id", Username: "your_username", Photo: "your_photo_url"},
		To:        "BROADCAST",
		Timestamp: time.Now().Format(time.RFC3339),
		Content:   Content{Likes: updatedLikes},
		Action:    "like",
		TablonID:  tablonID,
	}

	// Publicar en la red P2P
	go publishToP2P(likeMsg)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "message liked",
		"likes":  updatedLikes,
	})
}

func generateRandomInt(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func routeMessage(data []byte) ([]byte, error) {
	delay, err := generateRandomInt(1000)
	if err != nil {
		return nil, err
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
	return data, nil
}

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write(data)
	if err != nil {
		return nil, err
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	var out bytes.Buffer
	_, err = io.Copy(&out, reader)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func encryptMessage(message, key []byte) ([]byte, error) {
	// Ensure the key is exactly 32 bytes (256 bits) for AES-256
	hashedKey := sha256.Sum256(key)

	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Add additional authenticated data (AAD) for extra security
	// This is a timestamp that will be authenticated but not encrypted
	aad := []byte(fmt.Sprintf("%d", time.Now().UnixNano()))

	// Encrypt and authenticate the message
	ciphertext := aesgcm.Seal(nonce, nonce, message, aad)

	// Prepend the AAD length and AAD to the ciphertext
	aadLenBytes := make([]byte, 2)
	aadLenBytes[0] = byte(len(aad) >> 8)
	aadLenBytes[1] = byte(len(aad))

	// Final format: [aadLen(2 bytes)][aad][nonce(12 bytes)][ciphertext]
	result := append(aadLenBytes, aad...)
	return append(result, ciphertext...), nil
}

func decryptMessage(ciphertext, key []byte) ([]byte, error) {
	// Ensure the key is exactly 32 bytes (256 bits) for AES-256
	hashedKey := sha256.Sum256(key)

	// Check if the ciphertext is long enough to contain our header
	if len(ciphertext) < 2 {
		return nil, fmt.Errorf("ciphertext too short: missing AAD length")
	}

	// Extract the AAD length
	aadLen := int(ciphertext[0])<<8 | int(ciphertext[1])
	ciphertext = ciphertext[2:]

	// Check if the ciphertext is long enough to contain the AAD
	if len(ciphertext) < aadLen {
		return nil, fmt.Errorf("ciphertext too short: missing AAD")
	}

	// Extract the AAD
	aad := ciphertext[:aadLen]
	ciphertext = ciphertext[aadLen:]

	// Check if the ciphertext is long enough to contain the nonce
	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("ciphertext too short: missing nonce")
	}

	// Extract the nonce
	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

	// Create the AES cipher
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Create the GCM instance
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Decrypt the message
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

func serializeMessage(msg Message, keys [][]byte) ([]byte, error) {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	compressedData, err := compress(msgBytes)
	if err != nil {
		return nil, err
	}
	return mixnetEncrypt(compressedData, keys)
}

func deserializeMessage(data []byte, keys [][]byte) (Message, error) {
	decryptedData, err := mixnetDecrypt(data, keys)
	if err != nil {
		return Message{}, err
	}
	decompressedData, err := decompress(decryptedData)
	if err != nil {
		return Message{}, err
	}

	var msg Message
	err = json.Unmarshal(decompressedData, &msg)
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}

func mixnetEncrypt(message []byte, keys [][]byte) ([]byte, error) {
	ciphertext := message
	for _, key := range keys {
		var err error
		ciphertext, err = encryptMessage(ciphertext, key)
		if err != nil {
			return nil, err
		}
	}
	return ciphertext, nil
}

func mixnetDecrypt(ciphertext []byte, keys [][]byte) ([]byte, error) {
	plaintext := ciphertext
	for i := len(keys) - 1; i >= 0; i-- {
		var err error
		plaintext, err = decryptMessage(plaintext, keys[i])
		if err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}

func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get("Authorization")
		if tokenHeader == "" {
			http.Error(w, "Missing auth token", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(tokenHeader, " ")
		if len(parts) != 2 {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}
		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method")
			}
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid auth token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func generateTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
		PeerId   string `json:"peerId"`
		Photo    string `json:"photo"`
	}

	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !validateCredentials(credentials.Username, credentials.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	claims := jwt.MapClaims{
		"authorized": true,
		"username":   credentials.Username,
		"peerId":     credentials.PeerId,
		"photo":      credentials.Photo,
		"exp":        time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		http.Error(w, "Error al generar el token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Query().Get("title")
	if title == "" {
		title = "Notificaciones"
	}

	messageContent := r.URL.Query().Get("message")
	if messageContent == "" {
		http.Error(w, "Missing 'message' query parameter", http.StatusBadRequest)
		return
	}

	subtitle := r.URL.Query().Get("subtitle")
	if subtitle == "" {
		subtitle = "Sistema"
	}

	likes := 0
	if likesParam := r.URL.Query().Get("likes"); likesParam != "" {
		fmt.Sscanf(likesParam, "%d", &likes)
	}

	subscribed := false
	if subscribedParam := r.URL.Query().Get("subscribed"); subscribedParam != "" {
		subscribed = subscribedParam == "true"
	}

	msg := Message{
		ID:        generateMessageID(),
		From:      UserInfo{PeerID: "your_peer_id", Username: "your_username", Photo: "your_photo_url"},
		To:        "DESTINATION_PEER_ID",
		Timestamp: time.Now().Format(time.RFC3339),
		Content: Content{
			Title:      title,
			Message:    messageContent,
			Subtitle:   subtitle,
			Likes:      likes,
			Comments:   []Comment{},
			Subscribed: subscribed,
		},
	}

	messagesMutex.Lock()
	receivedMessages = append(receivedMessages, msg)
	messagesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"status": "message received"}
	json.NewEncoder(w).Encode(response)
}

func receiveMessagesHandler(w http.ResponseWriter, r *http.Request) {
	messagesMutex.Lock()
	defer messagesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(receivedMessages)
}

func main() {
	config, err := readConfig()
	if err != nil {
		log.Fatalf(Red+"Failed to read config: %v"+Reset, err)
	}

	r := mux.NewRouter()

	// API routes
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/createTablon", createTablonHandler).Methods("POST")
	api.HandleFunc("/readTablon", readTablonHandler).Methods("GET")
	api.HandleFunc("/deleteTablon", deleteTablonHandler).Methods("DELETE")
	api.HandleFunc("/addMessage", addMessageToTablonHandler).Methods("POST")
	api.HandleFunc("/deleteMessage", deleteMessageHandler).Methods("DELETE")
	api.HandleFunc("/likeMessage", likeMessageHandler).Methods("POST")
	api.HandleFunc("/send", sendMessageHandler).Methods("POST")
	api.HandleFunc("/recibe", receiveMessagesHandler).Methods("GET")
	api.HandleFunc("/generateToken", generateTokenHandler).Methods("GET")
	api.HandleFunc("/login", generateTokenHandler).Methods("POST")
	// Add new routes for binary transfer
	api.HandleFunc("/api/sendBinary", sendBinaryHandler).Methods("POST")
	api.HandleFunc("/api/receiveBinary", receiveBinaryHandler).Methods("POST")
	//http://localhost:8080/api/generateToken?username=victor/

	// Middleware CORS
	corsMiddleware := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)

	// Middleware para añadir cabeceras de seguridad
	securityMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			next.ServeHTTP(w, r)
		})
	}

	// Aplicar middleware CORS y de seguridad a todas las rutas
	r.Use(corsMiddleware)
	r.Use(securityMiddleware)

	// Servir archivos estáticos
	fs := http.FileServer(http.Dir("./web"))
	r.PathPrefix("/").Handler(fs)

	// Iniciar servidor HTTP
	go func() {
		log.Println("Starting HTTP server on :8080")
		if err := http.ListenAndServe(":8080", r); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Configuración de libp2p y pubsub
	ctx := context.Background()

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(config.ListenAddress),
		libp2p.NATPortMap(),
	)
	if err != nil {
		log.Fatalf(Red+"Failed to create host: %v"+Reset, err)
	}

	if config.Mdns.Enabled {
		if err := setupMDNS(ctx, h, config.Mdns.ServiceTag); err != nil {
			log.Fatalf(Red+"Failed to setup mDNS: %v"+Reset, err)
		}
	}

	go discoverPeers(ctx, h, config.TopicName)

	ps, err := pubsub.NewGossipSub(ctx, h, pubsub.WithMaxMessageSize(config.MaxMessageSize))
	if err != nil {
		log.Fatalf(Red+"Failed to create pubsub: %v"+Reset, err)
	}

	p2pTopic, err = ps.Join(hashTopic(config.TopicName))
	if err != nil {
		log.Fatalf(Red+"Failed to join topic: %v"+Reset, err)
	}

	p2pSub, err = p2pTopic.Subscribe()
	if err != nil {
		log.Fatalf(Red+"Failed to subscribe to topic: %v"+Reset, err)
	}

	// Generate multiple encryption keys from the master key
	p2pKeys = deriveEncryptionKeys(config.EncryptionKey, 3)

	// Start key rotation in a separate goroutine
	go rotateEncryptionKeys(config.EncryptionKey, 3*time.Hour)

	go handleP2PMessages(ctx)

	select {}
}

// Update the handleP2PMessages function to handle binary transfers
func handleP2PMessages(ctx context.Context) {
	for {
		m, err := p2pSub.Next(ctx)
		if err != nil {
			log.Printf("Failed to get next message: %v", err)
			continue
		}

		// Lock the mutex to safely access the encryption keys
		p2pKeysMutex.Lock()
		keys := p2pKeys // Make a local copy of the keys
		p2pKeysMutex.Unlock()

		// Deserialize the message with the current keys
		msg, err := deserializeMessage(m.Message.Data, keys)
		if err != nil {
			log.Printf("Deserialization error: %v", err)
			continue
		}

		// Handle binary transfer messages
		if msg.Action == "binary_transfer" {
			log.Printf("Received binary file: %s", msg.FileName)
			// Process the binary data (e.g., save to disk)
			receivedDir := "received_files"
			if err := os.MkdirAll(receivedDir, 0755); err != nil {
				log.Printf("Error creating directory for received files: %v", err)
				continue
			}
			outputPath := filepath.Join(receivedDir, fmt.Sprintf("%s_%s", msg.ID, msg.FileName))
			err = decodeBase64ToFile(msg.BinaryData, outputPath)
			if err != nil {
				log.Printf("Error saving received file: %v", err)
				continue
			}
			log.Printf("File saved to: %s", outputPath)
		} else {
			// Process other message types as before
			processP2PMessage(msg)
		}
	}
}
func createOrUpdateMessage(msg Message) {
	var targetTablon *Tablon
	for i, tablon := range tablones {
		if tablon.ID == msg.TablonID {
			targetTablon = &tablones[i]
			break
		}
	}

	if targetTablon == nil {
		newTablon := Tablon{
			ID:       msg.TablonID,
			Name:     msg.Content.Title,
			Messages: []Message{},
			Geo:      "", // Puedes ajustar esto según sea necesario
		}
		tablones = append(tablones, newTablon)
		targetTablon = &tablones[len(tablones)-1]
	}

	// Buscar si el mensaje ya existe
	for i, existingMsg := range targetTablon.Messages {
		if existingMsg.ID == msg.ID {
			// Actualizar mensaje existente
			targetTablon.Messages[i] = msg
			return
		}
	}

	// Añadir nuevo mensaje
	targetTablon.Messages = append(targetTablon.Messages, msg)
}

func deleteTablon(tablonID string) {
	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			tablones = append(tablones[:i], tablones[i+1:]...)
			break
		}
	}
}

func deleteMessage(tablonID, messageID string) {
	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			for j, message := range tablon.Messages {
				if message.ID == messageID {
					tablones[i].Messages = append(tablon.Messages[:j], tablon.Messages[j+1:]...)
					return
				}
			}
		}
	}
}

func updateMessageLikes(tablonID, messageID string, likes int) {
	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			for j, message := range tablon.Messages {
				if message.ID == messageID {
					tablones[i].Messages[j].Content.Likes = likes
					return
				}
			}
		}
	}
}

func processP2PMessage(msg Message) {
	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	switch msg.Action {
	case "create":
		// Crear o actualizar mensaje
		createOrUpdateMessage(msg)
	case "delete":
		// Eliminar mensaje o tablón
		if msg.TablonID == "" {
			deleteTablon(msg.ID)
		} else {
			deleteMessage(msg.TablonID, msg.ID)
		}
	case "like":
		// Actualizar likes
		updateMessageLikes(msg.TablonID, msg.ID, msg.Content.Likes)
	}
}

func setupMDNS(ctx context.Context, h host.Host, serviceTag string) error {
	service := mdns.NewMdnsService(h, serviceTag, &mdnsNotifee{h: h})
	return service.Start()
}

type mdnsNotifee struct {
	h host.Host
}

func executeSystemCommand(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing command: %v, stderr: %s", err, stderr.String())
	}
	return out.String(), nil
}

func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.h.ID() {
		return
	}
	if err := n.h.Connect(context.Background(), pi); err != nil {
		log.Printf(Red+"Failed to connect to peer found by mDNS: %v"+Reset, err)
	} else {
		log.Printf(Green+"Connected to peer found by mDNS: %s"+Reset, pi.ID)
	}
}

func hashTopic(topic string) string {
	hash := sha256.Sum256([]byte(topic))
	return hex.EncodeToString(hash[:])
}

func initDHT(ctx context.Context, h host.Host) *dht.IpfsDHT {
	kademliaDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeAuto))
	if err != nil {
		log.Fatalf(Red+"Failed to create DHT: %v"+Reset, err)
	}
	if err = kademliaDHT.Bootstrap(ctx); err != nil {
		log.Fatalf(Red+"Failed to bootstrap DHT: %v"+Reset, err)
	}
	var wg sync.WaitGroup
	for _, peerAddr := range dht.DefaultBootstrapPeers {
		peerinfo, _ := peer.AddrInfoFromP2pAddr(peerAddr)
		wg.Add(1)
		go func(peerinfo peer.AddrInfo) {
			defer wg.Done()
			if err := h.Connect(ctx, peerinfo); err != nil {
				//log.Printf(Yellow+"Bootstrap warning: %v"+Reset, err)
			}
		}(*peerinfo)
	}
	wg.Wait()

	return kademliaDHT
}

func discoverPeers(ctx context.Context, h host.Host, topicName string) {
	kademliaDHT := initDHT(ctx, h)
	routingDiscovery := drouting.NewRoutingDiscovery(kademliaDHT)
	dutil.Advertise(ctx, routingDiscovery, topicName)

	anyConnected := false
	for !anyConnected {
		log.Println(Blue + "Searching for peers..." + Reset)
		peerChan, err := routingDiscovery.FindPeers(ctx, topicName)
		if err != nil {
			log.Fatalf(Red+"Failed to find peers: %v"+Reset, err)
		}
		for peer := range peerChan {
			if peer.ID == h.ID() {
				continue
			}
			if err := h.Connect(ctx, peer); err != nil {
				//log.Printf(Yellow+"Failed connecting to %s, error: %s\n"+Reset, peer.ID, err)
			} else {
				log.SetOutput(os.Stdout)
				log.SetFlags(0)

				log.Println(Green+"Connected to: "+Reset, peer.ID)
				anyConnected = true
			}
		}
	}
	log.Println(Green + "Peer discovery complete" + Reset)
}

func streamConsoleTo(ctx context.Context, topic *pubsub.Topic, keys [][]byte, retryInterval int, from string, to string) {
	reader := bufio.NewReader(os.Stdin)
	maxRetries := 5
	for {
		s, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf(Red+"Failed to read input: %v"+Reset, err)
		}
		s = strings.TrimSpace(s)

		msg := Message{
			ID:        generateMessageID(),
			From:      UserInfo{PeerID: from, Username: "Usuario", Photo: "https://i0.wp.com/neumaticossanper.es/wp-content/uploads/2022/12/logo-oferta-png-4-1.png"},
			To:        to,
			Timestamp: time.Now().Format(time.RFC3339),
			Content: Content{
				Title:      "Notificacion",
				Message:    s,
				Subtitle:   "Sistema",
				Likes:      0,
				Comments:   []Comment{},
				Subscribed: false,
			},
		}

		// Lock the mutex to safely access the encryption keys
		p2pKeysMutex.Lock()
		currentKeys := p2pKeys // Make a local copy of the keys
		p2pKeysMutex.Unlock()

		serializedMsg, err := serializeMessage(msg, currentKeys)
		if err != nil {
			log.Printf(Red+"Failed to serialize message: %v"+Reset, err)
			continue
		}

		for i := 0; i < maxRetries; i++ {
			if err := topic.Publish(ctx, serializedMsg); err != nil {
				log.Printf(Red+"Publish error: %v, retrying... (%d/%d)"+Reset, err, i+1, maxRetries)
				time.Sleep(time.Duration(retryInterval) * time.Millisecond * time.Duration(1<<i))
			} else {
				break
			}
		}
	}
}

func printMessagesFrom(ctx context.Context, sub *pubsub.Subscription, keys [][]byte) {
	for {
		m, err := sub.Next(ctx)
		if err != nil {
			log.Fatalf(Red+"Failed to get next message: %v"+Reset, err)
		}

		// Lock the mutex to safely access the encryption keys
		p2pKeysMutex.Lock()
		currentKeys := p2pKeys // Make a local copy of the keys
		p2pKeysMutex.Unlock()

		msg, err := deserializeMessage(m.Message.Data, currentKeys)
		if err != nil {
			log.Printf(Red+"Deserialization error: %v"+Reset, err)
			continue
		}

		// p2p log
		// Imprimir el contenido del mensaje
		fmt.Println("Mensaje recibido:")
		fmt.Println("De:", msg.From.Username)
		fmt.Println("Contenido:", msg.Content.Message)
		fmt.Println("Likes:", msg.Content.Likes)
		fmt.Println("Fecha:", msg.Timestamp)
		fmt.Println(m.Message.Data)
		fmt.Println("----------------------------------")
		//
		msg.From.Username = "Administrador"

		messagesMutex.Lock()
		receivedMessages = append(receivedMessages, msg)
		messagesMutex.Unlock()

		log.Println(Blue + fmt.Sprintf("%s", msg.Content.Message) + Reset)
	}
}

func generateMessageID() string {
	return fmt.Sprintf("msg_%d", time.Now().UnixNano())
}

// deriveEncryptionKeys generates multiple encryption keys from a master key
func deriveEncryptionKeys(masterKey string, count int) [][]byte {
	// Ensure we have a strong master key by hashing it
	masterHash := sha256.Sum256([]byte(masterKey))

	// Create the specified number of derived keys
	keys := make([][]byte, count)

	// The first key is the master key hash
	keys[0] = masterHash[:]

	// Generate additional keys by repeatedly hashing with a salt
	for i := 1; i < count; i++ {
		// Create a unique salt for each key
		salt := fmt.Sprintf("key-%d-%s", i, masterKey)

		// Hash the previous key with the salt
		hasher := sha256.New()
		hasher.Write(keys[i-1])
		hasher.Write([]byte(salt))

		// Store the new key
		keys[i] = hasher.Sum(nil)
	}

	log.Printf(Green+"Generated %d encryption keys from master key"+Reset, count)
	return keys
}

// rotateEncryptionKeys periodically rotates the encryption keys for better security
func rotateEncryptionKeys(masterKey string, interval time.Duration) {
	// Create a ticker that triggers at the specified interval
	ticker := time.NewTicker(interval)

	// Add some randomness to the first rotation to avoid predictable patterns
	randomValue, err := rand.Int(rand.Reader, big.NewInt(int64(interval/2)))
	if err != nil {
		log.Printf(Red+"Failed to generate random delay: %v"+Reset, err)
		randomValue = big.NewInt(0)
	}
	initialDelay := time.Duration(randomValue.Int64())
	time.Sleep(initialDelay)

	// Start the rotation loop
	for range ticker.C {
		// Lock the global mutex before updating the keys
		p2pKeysMutex.Lock()

		// Generate new keys with a timestamp to ensure uniqueness
		newKeys := deriveEncryptionKeys(masterKey+fmt.Sprintf("-%d", time.Now().UnixNano()), 3)

		// Update the global keys
		p2pKeys = newKeys

		// Unlock the mutex
		p2pKeysMutex.Unlock()

		log.Printf(Yellow+"Encryption keys rotated at %s"+Reset, time.Now().Format(time.RFC3339))
	}
}
