package onion

import (
	"crypto/rsa"
	"sync"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// Constantes para tipos de mensajes de control
const (
	MsgTypeNodeAnnouncement = "node_announcement"
	MsgTypeKeyExchange      = "key_exchange"
	MsgTypeRouteUpdate      = "route_update"
	MsgTypeNetworkStatus    = "network_status"
)

// Variables globales para el sistema de enrutamiento cebolla
var (
	// ID de este nodo
	NodeID string

	// Clave privada de este nodo
	NodePrivateKey *rsa.PrivateKey

	// Mapa de nodos conocidos (ID -> Clave pública)
	KnownNodes     = make(map[string]*rsa.PublicKey)
	KnownNodesMutex = &sync.RWMutex{}

	// Mapa de rutas conocidas (Destino -> Ruta)
	KnownRoutes     = make(map[string][]string)
	KnownRoutesMutex = &sync.RWMutex{}

	// Variables globales para el topic de control
	ControlTopic *pubsub.Topic
	ControlSub   *pubsub.Subscription

	// Deshabilitar el enrutamiento de cebolla simulado
	DisableRoutingHops = false
)

// OnionLayer representa una capa de enrutamiento cebolla
type OnionLayer struct {
	// Siguiente salto en la ruta
	NextHop string `json:"next_hop"`

	// Destino final
	FinalDest string `json:"final_dest"`

	// Índice de la capa
	LayerIndex int `json:"layer_index"`

	// Tipo de carga útil (message o layer)
	PayloadType string `json:"payload_type"`
}
