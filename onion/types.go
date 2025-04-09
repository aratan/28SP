package onion

import (
	"crypto/rsa"
	"sync"
	"time"
)

// Variables globales para el enrutamiento cebolla
var (
	// Clave privada de este nodo
	NodePrivateKey *rsa.PrivateKey

	// ID de este nodo (derivado de la clave pública)
	NodeID string

	// Mapa de nodos conocidos (ID -> clave pública)
	KnownNodes      = make(map[string]*rsa.PublicKey)
	KnownNodesMutex sync.RWMutex

	// Mapa de rutas conocidas (destino -> [nodos intermedios])
	KnownRoutes      = make(map[string][]string)
	KnownRoutesMutex sync.RWMutex

	// Deshabilitar el enrutamiento de cebolla simulado
	DisableRoutingHops = false
)

// Tipos de mensajes de control
const (
	MsgTypeNodeAnnouncement = "node_announcement"
	MsgTypeKeyExchange      = "key_exchange"
	MsgTypeRouteUpdate      = "route_update"
	MsgTypeNetworkStatus    = "network_status"
)

// Estructura para representar un nodo en la red
type OnionNode struct {
	ID        string         // ID del nodo (derivado de la clave pública)
	PublicKey *rsa.PublicKey // Clave pública del nodo
	LastSeen  time.Time      // Última vez que se vio al nodo
}

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
