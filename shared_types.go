package main

import (
	"crypto/rsa"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
)

// Variables globales compartidas
var (
	// Topic P2P
	P2PTopic *pubsub.Topic
	P2PSub   *pubsub.Subscription
	P2PKeys  [][]byte

	// Host libp2p
	P2PHost host.Host
	PS      *pubsub.PubSub

	// Variable para controlar si se usan saltos para pruebas
	DisableRoutingHops = false // Habilitamos el enrutamiento de cebolla para mejorar la protección contra análisis de metadatos
)

// Constantes para colores en la consola
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Reset  = "\033[0m"
)

// Message representa un mensaje en la red P2P
type Message struct {
	ID              string   `json:"id"`
	From            UserInfo `json:"from"`
	To              string   `json:"to"`
	TablonID        string   `json:"tablonId"`
	Content         Content  `json:"content"`
	Timestamp       int64    `json:"timestamp"`
	Likes           int      `json:"likes"`
	Encrypted       bool     `json:"encrypted"`
	AnonymousSender bool     `json:"anonymousSender"`
	Route           []string `json:"route,omitempty"`      // Ruta para enrutamiento cebolla
	CurrentHop      int      `json:"currentHop,omitempty"` // Salto actual en la ruta
	EncryptedLayers [][]byte `json:"encryptedLayers,omitempty"` // Capas cifradas para cada nodo
}

// UserInfo representa información de un usuario
type UserInfo struct {
	PeerID   string `json:"peerId"`
	Username string `json:"username"`
	Photo    string `json:"photo"`
}

// Content representa el contenido de un mensaje
type Content struct {
	Title      string    `json:"title"`
	Message    string    `json:"message"`
	Subtitle   string    `json:"subtitle"`
	Comments   []Comment `json:"comments"`
	Subscribed bool      `json:"subscribed"`
}

// Comment representa un comentario en un mensaje
type Comment struct {
	Username string `json:"username"`
	Comment  string `json:"comment"`
}

// Tablon representa un tablón de mensajes
type Tablon struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Messages []Message `json:"messages"`
	Geo      string    `json:"geo"`
}

// Variables para tablones
var (
	Tablones      []Tablon
	TableonesMutex sync.Mutex
)

// Variables para mensajes recibidos
var (
	ReceivedMessages []Message
	MessagesMutex    sync.Mutex
)

// Variables para el mapeo de nombres de archivo (protección de metadatos)
var (
	FileNameMapping      = make(map[string]string)
	FileNameMappingMutex sync.Mutex
)

// SecurityConfig representa la configuración de seguridad
type SecurityConfig struct {
	EndToEndEncryption bool
	EncryptionKey      string
	KeyRotation        bool
	KeyRotationInterval int
	OnionRouting       bool
	MinHops            int
	MaxHops            int
	AnonymousMessages  bool
	AnonymitySetSize   int
	TrafficMixing      bool
	TrafficMixingInterval int
	DummyMessages      bool
	DummyMessageInterval int
	MessageTTL         int
}

// Variables para la configuración de seguridad
var (
	SecurityConfigInstance SecurityConfig
)

// OnionNode representa un nodo en la red de enrutamiento cebolla
type OnionNode struct {
	ID        string
	PublicKey *rsa.PublicKey
}

// OnionRoute representa una ruta en la red de enrutamiento cebolla
type OnionRoute struct {
	Destination string
	Route       []string
}
