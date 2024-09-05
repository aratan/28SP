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
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strconv"
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

// Constants
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Reset  = "\033[0m"
)

// Global variables
var (
	topicNameFlag = flag.String("topicName", "applesauce", "name of topic to join")
	jwtSecretKey  = []byte("your-256-bit-secret")
	tablones      []Tablon
	tablonesMutex sync.Mutex
	receivedMessages []Message
	messagesMutex sync.Mutex
	logger        *log.Logger
)

// Config struct
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

// Message struct
type Message struct {
	ID        string   `json:"id"`
	From      UserInfo `json:"from"`
	To        string   `json:"to"`
	Timestamp string   `json:"timestamp"`
	Content   Content  `json:"content"`
}

// Tablon struct
type Tablon struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Messages []Message `json:"messages"`
	Geo      string    `json:"geo"`
	Likes    int       `json:"likes"`
}

// UserInfo struct
type UserInfo struct {
	PeerID   string `json:"peerId"`
	Username string `json:"username"`
	Photo    string `json:"photo"`
}

// Content struct
type Content struct {
	Title      string    `json:"title"`
	Message    string    `json:"message"`
	Subtitle   string    `json:"subtitle"`
	Likes      int       `json:"likes"`
	Comments   []Comment `json:"comments"`
	Subscribed bool      `json:"subscribed"`
}

// Comment struct
type Comment struct {
	Username string `json:"username"`
	Comment  string `json:"comment"`
}

// readConfig reads the configuration file
func readConfig() (*Config, error) {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &config, nil
}

// createTablonHandler handles the creation of a new Tablon
func createTablonHandler(w http.ResponseWriter, r *http.Request) {
	tablonName := r.URL.Query().Get("name")
	if tablonName == "" {
		http.Error(w, "Missing 'name' query parameter", http.StatusBadRequest)
		return
	}

	mensaje := r.URL.Query().Get("mensaje")
	geo := r.URL.Query().Get("geo")
	horario := r.URL.Query().Get("horario")
	iglesia := r.URL.Query().Get("iglesia")
	dia := r.URL.Query().Get("dia")

	msg := Message{
		ID:        generateMessageID(),
		From:      UserInfo{PeerID: "your_peer_id", Username: "your_username", Photo: "your_photo_url"},
		To:        "DESTINATION_PEER_ID",
		Timestamp: time.Now().Format(time.RFC3339),
		Content: Content{
			Title:      "Nuevo Mensaje",
			Message:    mensaje,
			Subtitle:   "Información de la Iglesia",
			Likes:      0,
			Comments:   []Comment{},
			Subscribed: false,
		},
	}

	tablon := Tablon{
		ID:       generateMessageID(),
		Name:     tablonName,
		Messages: []Message{msg},
		Geo:      geo,
		Likes:    0,
	}

	tablonesMutex.Lock()
	tablones = append(tablones, tablon)
	tablonesMutex.Unlock()

	response := map[string]string{
		"status":   "tablon created",
		"id":       tablon.ID,
		"name":     tablonName,
		"mensaje":  mensaje,
		"geo":      geo,
		"horario":  horario,
		"iglesia":  iglesia,
		"dia":      dia,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// addLikeToTablonHandler handles adding a like to a Tablon
func addLikeToTablonHandler(w http.ResponseWriter, r *http.Request) {
	tablonID := r.URL.Query().Get("tablon_id")
	if tablonID == "" {
		http.Error(w, "Missing 'tablon_id' query parameter", http.StatusBadRequest)
		return
	}

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	for i, tablon := range tablones {
		if tablon.ID == tablonID {
			tablones[i].Likes++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "like added",
				"likes":  fmt.Sprintf("%d", tablones[i].Likes),
			})
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}

// addMessageToTablonHandler handles adding a message to a Tablon
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
				To:        "DESTINATION_PEER_ID",
				Timestamp: time.Now().Format(time.RFC3339),
				Content: Content{
					Title:      "Nuevo Mensaje",
					Message:    messageContent,
					Subtitle:   "Sistema",
					Likes:      0,
					Comments:   []Comment{},
					Subscribed: false,
				},
			}

			tablones[i].Messages = append(tablones[i].Messages, msg)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "message added"})
			return
		}
	}

	http.Error(w, "Tablon not found", http.StatusNotFound)
}

// readTablonHandler handles reading all Tablones
func readTablonHandler(w http.ResponseWriter, r *http.Request) {
	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tablones)
}

// generateRandomInt generates a random integer
func generateRandomInt(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int: %w", err)
	}
	return int(n.Int64()), nil
}

// routeMessage simulates message routing
func routeMessage(data []byte) ([]byte, error) {
	delay, err := generateRandomInt(1000)
	if err != nil {
		return nil, fmt.Errorf("failed to generate delay: %w", err)
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
	return data, nil
}

// compress compresses data using gzip
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write compressed data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}
	return buf.Bytes(), nil
}

// decompress decompresses gzipped data
func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	var out bytes.Buffer
	if _, err := io.Copy(&out, reader); err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}
	return out.Bytes(), nil
}

// encryptMessage encrypts a message using AES-GCM
func encryptMessage(message, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := aesgcm.Seal(nonce, nonce, message, nil)
	return ciphertext, nil
}

// decryptMessage decrypts a message using AES-GCM
func decryptMessage(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// serializeMessage serializes and encrypts a message
func serializeMessage(msg Message, keys [][]byte) ([]byte, error) {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}
	compressedData, err := compress(msgBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compress message: %w", err)
	}
	return mixnetEncrypt(compressedData, keys)
}

// deserializeMessage decrypts and deserializes a message
func deserializeMessage(data []byte, keys [][]byte) (Message, error) {
	decryptedData, err := mixnetDecrypt(data, keys)
	if err != nil {
		return Message{}, fmt.Errorf("failed to decrypt message: %w", err)
	}
	decompressedData, err := decompress(decryptedData)
	if err != nil {
		return Message{}, fmt.Errorf("failed to decompress message: %w", err)
	}

	var msg Message
	if err := json.Unmarshal(decompressedData, &msg); err != nil {
		return Message{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}
	return msg, nil
}

// mixnetEncrypt encrypts data through multiple layers
func mixnetEncrypt(message []byte, keys [][]byte) ([]byte, error) {
	ciphertext := message
	for _, key := range keys {
		var err error
		ciphertext, err = encryptMessage(ciphertext, key)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt layer: %w", err)
		}
	}
	return ciphertext, nil
}

// mixnetDecrypt decrypts data through multiple layers
func mixnetDecrypt(ciphertext []byte, keys [][]byte) ([]byte, error) {
	plaintext := ciphertext
	for i := len(keys) - 1; i >= 0; i-- {
		var err error
		plaintext, err = decryptMessage(plaintext, keys[i])
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt layer: %w", err)
		}
	}
	return plaintext, nil
}

// authenticate middleware for JWT authentication
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
				return nil, fmt.Errorf("unexpected signing method")
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

// generateTokenHandler generates a new JWT token
func generateTokenHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Missing 'username' query parameter", http.StatusBadRequest)
		return
	}

	claims := jwt.MapClaims{
		"authorized": true,
		"user":       username,
		"exp":        time.Now().Add(time.Hour * 1).Unix(),
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

// sendMessageHandler handles sending a new message
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

// receiveMessagesHandler handles receiving all messages
func receiveMessagesHandler(w http.ResponseWriter, r *http.Request) {
	messagesMutex.Lock()
	defer messagesMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(receivedMessages)
}

// deleteTablonByIndexHandler handles deleting a Tablon by index
func deleteTablonByIndexHandler(w http.ResponseWriter, r *http.Request) {
	indexStr := r.URL.Query().Get("index")
	if indexStr == "" {
		http.Error(w, "Missing 'index' query parameter", http.StatusBadRequest)
		return
	}

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		http.Error(w, "Invalid 'index' query parameter", http.StatusBadRequest)
		return
	}

	tablonesMutex.Lock()
	defer tablonesMutex.Unlock()

	if index < 0 || index >= len(tablones) {
		http.Error(w, "Index out of range", http.StatusBadRequest)
		return
	}

	tablones = append(tablones[:index], tablones[index+1:]...)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "tablon deleted"})
}

// deleteMessageByIndexHandler handles deleting a message by index
func deleteMessageByIndexHandler(w http.ResponseWriter, r *http.Request) {
	indexStr := r.URL.Query().Get("index")
	if indexStr == "" {
		http.Error(w, "Missing 'index' query parameter", http.StatusBadRequest)
		return
	}

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		http.Error(w, "Invalid 'index' query parameter", http.StatusBadRequest)
		return
	}

	messagesMutex.Lock()
	defer messagesMutex.Unlock()

	if index < 0 || index >= len(receivedMessages) {
		http.Error(w, "Index out of range", http.StatusBadRequest)
		return
	}

	receivedMessages = append(receivedMessages[:index], receivedMessages[index+1:]...)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "message deleted"})
}

// addLikeToMessageHandler handles adding a like to a message
func addLikeToMessageHandler(w http.ResponseWriter, r *http.Request) {
	indexStr := r.URL.Query().Get("index")
	if indexStr == "" {
		http.Error(w, "Missing 'index' query parameter", http.StatusBadRequest)
		return
	}

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		http.Error(w, "Invalid 'index' query parameter", http.StatusBadRequest)
		return
	}

	messagesMutex.Lock()
	defer messagesMutex.Unlock()

	if index < 0 || index >= len(receivedMessages) {
		http.Error(w, "Index out of range", http.StatusBadRequest)
		return
	}

	receivedMessages[index].Content.Likes++

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "like added", "likes": fmt.Sprintf("%d", receivedMessages[index].Content.Likes)})
}

// setupMDNS sets up mDNS discovery
func setupMDNS(ctx context.Context, h host.Host, serviceTag string) error {
	service := mdns.NewMdnsService(h, serviceTag, &mdnsNotifee{h: h})
	return service.Start()
}

// mdnsNotifee implements the mdns.Notifee interface
type mdnsNotifee struct {
	h host.Host
}

// HandlePeerFound is called when a peer is discovered via mDNS
func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.h.ID() {
		return
	}
	if err := n.h.Connect(context.Background(), pi); err != nil {
		logger.Printf("Failed to connect to peer found by mDNS: %v", err)
	} else {
		logger.Printf("Connected to peer found by mDNS: %s", pi.ID)
	}
}

// executeSystemCommand executes a system command and returns its output
func executeSystemCommand(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing command: %w, stderr: %s", err, stderr.String())
	}
	return out.String(), nil
}

// hashTopic hashes a topic name
func hashTopic(topic string) string {
	hash := sha256.Sum256([]byte(topic))
	return hex.EncodeToString(hash[:])
}

// initDHT initializes the DHT
func initDHT(ctx context.Context, h host.Host) *dht.IpfsDHT {
	kademliaDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeAuto))
	if err != nil {
		logger.Fatalf("Failed to create DHT: %v", err)
	}
	if err = kademliaDHT.Bootstrap(ctx); err != nil {
		logger.Fatalf("Failed to bootstrap DHT: %v", err)
	}
	var wg sync.WaitGroup
	for _, peerAddr := range dht.DefaultBootstrapPeers {
		peerinfo, _ := peer.AddrInfoFromP2pAddr(peerAddr)
		wg.Add(1)
		go func(peerinfo peer.AddrInfo) {
			defer wg.Done()
			if err := h.Connect(ctx, peerinfo); err != nil {
				logger.Printf("Bootstrap warning: %v", err)
			}
		}(*peerinfo)
	}
	wg.Wait()

	return kademliaDHT
}

// discoverPeers discovers peers on the network
func discoverPeers(ctx context.Context, h host.Host, topicName string) {
	kademliaDHT := initDHT(ctx, h)
	routingDiscovery := drouting.NewRoutingDiscovery(kademliaDHT)
	dutil.Advertise(ctx, routingDiscovery, topicName)

	anyConnected := false
	for !anyConnected {
		logger.Println("Searching for peers...")
		peerChan, err := routingDiscovery.FindPeers(ctx, topicName)
		if err != nil {
			logger.Fatalf("Failed to find peers: %v", err)
		}
		for peer := range peerChan {
			if peer.ID == h.ID() {
				continue
			}
			if err := h.Connect(ctx, peer); err != nil {
				logger.Printf("Failed connecting to %s, error: %s", peer.ID, err)
			} else {
				logger.Printf("Connected to: %s", peer.ID)
				anyConnected = true
			}
		}
	}
	logger.Println("Peer discovery complete")
}

// streamConsoleTo streams console input to the network
func streamConsoleTo(ctx context.Context, topic *pubsub.Topic, keys [][]byte, retryInterval int, from string, to string) {
	reader := bufio.NewReader(os.Stdin)
	maxRetries := 5
	for {
		s, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			logger.Fatalf("Failed to read input: %v", err)
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
			logger.Printf("Failed to serialize message: %v", err)
			continue
		}

		for i := 0; i < maxRetries; i++ {
			if err := topic.Publish(ctx, serializedMsg); err != nil {
				logger.Printf("Publish error: %v, retrying... (%d/%d)", err, i+1, maxRetries)
				time.Sleep(time.Duration(retryInterval) * time.Millisecond * time.Duration(1<<i))
			} else {
				break
			}
		}
	}
}

// printMessagesFrom prints messages received from the network
func printMessagesFrom(ctx context.Context, sub *pubsub.Subscription, keys [][]byte) {
	for {
		m, err := sub.Next(ctx)
		if err != nil {
			logger.Fatalf("Failed to get next message: %v", err)
		}
		msg, err := deserializeMessage(m.Message.Data, keys)
		if err != nil {
			logger.Printf("Deserialization error: %v", err)
			continue
		}

		msg.From.Username = "Administrador"

		messagesMutex.Lock()
		receivedMessages = append(receivedMessages, msg)
		messagesMutex.Unlock()

		logger.Printf("%s", msg.Content.Message)
	}
}

// generateMessageID generates a unique message ID
func generateMessageID() string {
	return fmt.Sprintf("msg_%d", time.Now().UnixNano())
}

func main() {


	config, err := readConfig()
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	// Initialize logger
	logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	logger = log.New(logFile, "", log.LstdFlags)

	r := mux.NewRouter()

	// Routes that don't require authentication
	r.HandleFunc("/api/createTablon", createTablonHandler).Methods("POST")
    r.HandleFunc("/api/readTablon", readTablonHandler).Methods("GET")
    r.HandleFunc("/api/addLikeToTablon", addLikeToTablonHandler).Methods("POST")
    r.HandleFunc("/api/addMessage", addMessageToTablonHandler).Methods("POST")
    r.HandleFunc("/api/deleteTablonByIndex", deleteTablonByIndexHandler).Methods("DELETE")
    r.HandleFunc("/api/deleteMessageByIndex", deleteMessageByIndexHandler).Methods("DELETE")

	// Routes that require authentication
	api := r.PathPrefix("/api").Subrouter()
	api.Use(authenticate)
	api.HandleFunc("/send", sendMessageHandler).Methods("POST")
	api.HandleFunc("/addMessage", addMessageToTablonHandler).Methods("POST")
	api.HandleFunc("/deleteTablonByIndex", deleteTablonByIndexHandler).Methods("DELETE")
	api.HandleFunc("/deleteMessageByIndex", deleteMessageByIndexHandler).Methods("DELETE")

	headersOk := handlers.AllowedHeaders([]string{"Authorization", "Content-Type"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "POST", "DELETE", "OPTIONS"})

	go func() {
		if config.UseSSL {
			logger.Println("HTTPS server running on port 443")
			if err := http.ListenAndServeTLS(":443", "server.crt", "server.key", handlers.CORS(originsOk, headersOk, methodsOk)(r)); err != nil {
				logger.Fatalf("Failed to start HTTPS server: %v", err)
			}
		} else {
			logger.Println("HTTP server running on port 8080")
			if err := http.ListenAndServe(":8080", handlers.CORS(originsOk, headersOk, methodsOk)(r)); err != nil {
				logger.Fatalf("Failed to start HTTP server: %v", err)
			}
		}
	}()

	if len(config.EncryptionKey) != 16 && len(config.EncryptionKey) != 24 && len(config.EncryptionKey) != 32 {
		logger.Fatalf("Invalid encryption key length: %d", len(config.EncryptionKey))
	}

	keys := [][]byte{
		[]byte(config.EncryptionKey),
	}

	ctx := context.Background()

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(config.ListenAddress),
		libp2p.NATPortMap(),
	)
	if err != nil {
		logger.Fatalf("Failed to create host: %v", err)
	}

	if config.Mdns.Enabled {
		if err := setupMDNS(ctx, h, config.Mdns.ServiceTag); err != nil {
			logger.Fatalf("Failed to setup mDNS: %v", err)
		}
	}

	go discoverPeers(ctx, h, config.TopicName)

	ps, err := pubsub.NewGossipSub(ctx, h, pubsub.WithMaxMessageSize(config.MaxMessageSize))
	if err != nil {
		logger.Fatalf("Failed to create pubsub: %v", err)
	}

	hashedTopic := hashTopic(config.TopicName)
	topic, err := ps.Join(hashedTopic)
	if err != nil {
		logger.Fatalf("Failed to join topic: %v", err)
	}

	from := h.ID().String()
	to := "DESTINATION_PEER_ID"

	go streamConsoleTo(ctx, topic, keys, config.RetryInterval, from, to)

	sub, err := topic.Subscribe()
	if err != nil {
		logger.Fatalf("Failed to subscribe to topic: %v", err)
	}
	go printMessagesFrom(ctx, sub, keys)

	select {}
}