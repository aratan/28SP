package onion

import (
	"crypto/rsa"
	"time"
)

// Variables globales para el enrutamiento cebolla
// Nota: Las variables globales ahora están definidas en shared.go

// Tipos de mensajes de control
// Nota: Las constantes de tipos de mensajes ahora están definidas en shared.go

// Estructura para representar un nodo en la red
type OnionNode struct {
	ID        string         // ID del nodo (derivado de la clave pública)
	PublicKey *rsa.PublicKey // Clave pública del nodo
	LastSeen  time.Time      // Última vez que se vio al nodo
}

// Estructura para representar una capa de enrutamiento cebolla
// Nota: La estructura OnionLayer ahora está definida en shared.go

// Estructura para representar un mensaje de enrutamiento cebolla
type OnionMessage struct {
	Type       string `json:"type"`       // Tipo de mensaje: "onion"
	OriginNode string `json:"originNode"` // ID del nodo de origen
	CurrentHop string `json:"currentHop"` // ID del nodo actual
	Layer      []byte `json:"layer"`      // Capa cifrada para el nodo actual
	Payload    []byte `json:"payload"`    // Carga útil cifrada (siguiente capa o mensaje final)
}
