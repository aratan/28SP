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
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"

	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
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
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
)

var (
	topicNameFlag = flag.String("topicName", "applesauce", "name of topic to join")
	jwtSecretKey  = []byte("your-256-bit-secret")
)

var (
	p2pTopic *pubsub.Topic
	p2pSub   *pubsub.Subscription
	p2pKeys  [][]byte
)

const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Reset  = "\033[0m"
)
type Node struct {
	Hash        string `json:"hash"`
	IsConnected bool   `json:"isConnected"`
}

type NodeInfo struct {
	NodeHash       string `json:"nodeHash"`
	ConnectedNodes []Node `json:"connectedNodes"`
}
type RefreshToken struct {
	Token     string
	Username  string
	ExpiresAt time.Time
}

// Mapa para almacenar refresh tokens (en producción, usar una base de datos)
var refreshTokens = make(map[string]RefreshToken)

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
}
type User struct {
	Username     string
	PasswordHash string
	PeerID       string
	Photo        string
}

// Mapa para almacenar usuarios (en producción, usar una base de datos)
var users = map[string]User{
	"admin": {
		Username:     "admin",
		PasswordHash: "$2a$12$WBE8A/IK66orAJLfpTncPuGGq90KkiLfQq3SHGPYvt.SGpxfC/feW",
		// Hash de "123456" https://bcrypt-generator.com/
		PeerID: "admin_peer_id",
		Photo:  "https://example.com/admin.jpg",
	},
	"editor": {
		Username:     "user1",
		PasswordHash: "$2a$12$rG0VJ8fIC7mjavKfp6YYuuuUuvTf5fhRjlPZQve0K1gv1zPMgWQai", // Hash de "password"
		PeerID:       "user1_peer_id",
		Photo:        "https://example.com/user1.jpg",
	},
	// Añade más usuarios según sea necesario
}

type Message struct {
	ID        string   `json:"id"`
	From      UserInfo `json:"from"`
	To        string   `json:"to"`
	Timestamp string   `json:"timestamp"`
	Content   Content  `json:"content"`
	Action    string   `json:"action"` // "create", "delete", "like"
	TablonID  string   `json:"tablonId"`
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
func getPeerID() (string, error) {
    h, err := libp2p.New()
    if err != nil {
        return "", err
    }
    return h.ID().String(), nil
}

func nodeInfoHandler(w http.ResponseWriter, r *http.Request) {
    // Verificar el token JWT

    peerID, err := getPeerID()
    if err != nil {
        http.Error(w, "Error obteniendo el PeerID", http.StatusInternalServerError)
        return
    }

    // Aquí deberías obtener la información real del nodo y los nodos conectados
    nodeInfo := struct {
        NodeHash       string `json:"nodeHash"`
        ConnectedNodes []struct {
            Hash        string `json:"hash"`
            IsConnected bool   `json:"isConnected"`
        } `json:"connectedNodes"`
    }{
        NodeHash: peerID,
        ConnectedNodes: []struct {
            Hash        string `json:"hash"`
            IsConnected bool   `json:"isConnected"`
        }{
            {Hash: "0x" + peerID, IsConnected: true},
           
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(nodeInfo)
}

func generateRandomHash(length int) string {
	const charset = "abcdef0123456789"
	b := make([]byte, length)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[num.Int64()]
	}
	return string(b)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, exists := users[user.Username]; exists {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
	fmt.Println(hashedPassword)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	user.PasswordHash = string(hashedPassword)
	users[user.Username] = user

	w.WriteHeader(http.StatusCreated)
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, exists := users[loginData.Username]
	if !exists {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(loginData.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generar token JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"peerId":   user.PeerID,
		"exp":      time.Now().Add(time.Minute * 15).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Generar refresh token
	refreshToken, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
		return
	}

	// Almacenar refresh token
	refreshTokens[refreshToken] = RefreshToken{
		Token:     refreshToken,
		Username:  user.Username,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7), // El refresh token expira en 7 días
	}

	// Enviar respuesta
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":        tokenString,
		"refreshToken": refreshToken,
	})
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	refreshTokenInfo, exists := refreshTokens[requestBody.RefreshToken]
	if !exists || time.Now().After(refreshTokenInfo.ExpiresAt) {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	user, exists := users[refreshTokenInfo.Username]
	if !exists {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Generar nuevo token JWT
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"peerId":   user.PeerID,
		"exp":      time.Now().Add(time.Minute * 15).Unix(),
	})

	newTokenString, err := newToken.SignedString(jwtSecretKey)
	if err != nil {
		http.Error(w, "Error generating new access token", http.StatusInternalServerError)
		return
	}

	// Generar nuevo refresh token
	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "Error generating new refresh token", http.StatusInternalServerError)
		return
	}

	// Actualizar el mapa de refresh tokens
	delete(refreshTokens, requestBody.RefreshToken)
	refreshTokens[newRefreshToken] = RefreshToken{
		Token:     newRefreshToken,
		Username:  user.Username,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7),
	}

	// Enviar respuesta
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":        newTokenString,
		"refreshToken": newRefreshToken,
	})
}
func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
func verifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return token, nil
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing authorization token", http.StatusUnauthorized)
			return
		}

		token, err := verifyToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		username, ok := claims["username"].(string)
		if !ok {
			http.Error(w, "Invalid username claim", http.StatusUnauthorized)
			return
		}

		if _, exists := users[username]; !exists {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
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
	serializedMsg, err := serializeMessage(msg, p2pKeys)
	if err != nil {
		log.Printf(Red+"Failed to serialize message for P2P: %v"+Reset, err)
		return
	}

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
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, message, nil)
	return ciphertext, nil
}

func decryptMessage(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
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
	username := r.URL.Query().Get("username")
	peerId := r.URL.Query().Get("peerId")
	photo := r.URL.Query().Get("photo")

	if username == "" || peerId == "" {
		http.Error(w, "Missing 'username' or 'peerId' query parameter", http.StatusBadRequest)
		return
	}

	claims := jwt.MapClaims{
		"authorized": true,
		"username":   username,
		"peerId":     peerId,
		"photo":      photo,
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
	api.HandleFunc("/nodeInfo", nodeInfoHandler).Methods("GET")
	api.HandleFunc("/createTablon", createTablonHandler).Methods("POST")
	api.HandleFunc("/readTablon", readTablonHandler).Methods("GET")
	api.HandleFunc("/deleteTablon", deleteTablonHandler).Methods("DELETE")
	api.HandleFunc("/addMessage", addMessageToTablonHandler).Methods("POST")
	api.HandleFunc("/deleteMessage", deleteMessageHandler).Methods("DELETE")
	api.HandleFunc("/likeMessage", likeMessageHandler).Methods("POST")
	api.HandleFunc("/send", sendMessageHandler).Methods("POST")
	api.HandleFunc("/recibe", receiveMessagesHandler).Methods("GET")
	api.HandleFunc("/generateToken", generateTokenHandler).Methods("GET")
	api.HandleFunc("/login", loginHandler)
	api.HandleFunc("/refresh", refreshTokenHandler)
	api.HandleFunc("/protected", authMiddleware(protectedHandler))
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

	p2pKeys = [][]byte{[]byte(config.EncryptionKey)}

	go handleP2PMessages(ctx)

	select {}
}
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Este es un ejemplo de un manejador protegido que requiere autenticación
	w.Write([]byte("This is a protected resource"))
}
func handleP2PMessages(ctx context.Context) {
	for {
		m, err := p2pSub.Next(ctx)
		if err != nil {
			log.Printf(Red+"Failed to get next message: %v"+Reset, err)
			continue
		}
		msg, err := deserializeMessage(m.Message.Data, p2pKeys)
		if err != nil {
			log.Printf(Red+"Deserialization error: %v"+Reset, err)
			continue
		}

		// Procesar el mensaje P2P
		processP2PMessage(msg)
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
		serializedMsg, err := serializeMessage(msg, keys)
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
		msg, err := deserializeMessage(m.Message.Data, keys)
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
