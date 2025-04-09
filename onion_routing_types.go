package main

import (
	"crypto/rsa"
)

// Estructura para representar un nodo en la red de enrutamiento cebolla
type OnionNode struct {
	ID        string         // ID del nodo (PeerID)
	PublicKey *rsa.PublicKey // Clave pública del nodo
}

// Estructura para representar una capa de enrutamiento cebolla
type OnionLayer struct {
	NextHop       string `json:"nextHop"`       // ID del siguiente nodo
	EncryptedData []byte `json:"encryptedData"` // Datos cifrados para el siguiente nodo
}

// Estructura para representar un mensaje de enrutamiento cebolla
type OnionMessage struct {
	Type        string     `json:"type"`        // Tipo de mensaje: "data" o "route"
	CurrentHop  string     `json:"currentHop"`  // ID del nodo actual
	NextHop     string     `json:"nextHop"`     // ID del siguiente nodo
	FinalDest   string     `json:"finalDest"`   // ID del destino final
	Layer       OnionLayer `json:"layer"`       // Capa actual del mensaje
	OriginalMsg []byte     `json:"originalMsg"` // Mensaje original (solo presente en el destino final)
}
