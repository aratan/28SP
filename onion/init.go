package onion

import (
	"context"
	"fmt"
	"log"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// Inicializar el sistema de enrutamiento cebolla
func InitOnionRouting(ctx context.Context, ps *pubsub.PubSub) error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")

	// Inicializar el sistema de claves
	if err := InitKeySystem(); err != nil {
		return fmt.Errorf("error al inicializar sistema de claves: %v", err)
	}

	// Inicializar el topic de control
	if err := InitControlTopic(ctx, ps); err != nil {
		return fmt.Errorf("error al inicializar topic de control: %v", err)
	}

	// Anunciar la presencia de este nodo
	if err := AnnounceNode(); err != nil {
		return fmt.Errorf("error al anunciar nodo: %v", err)
	}

	// Programar anuncios periódicos
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := AnnounceNode(); err != nil {
					log.Printf("Error al anunciar nodo periódicamente: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Deshabilitar el enrutamiento de cebolla simulado
	DisableRoutingHops = false

	log.Printf("Sistema de enrutamiento cebolla real inicializado correctamente")
	return nil
}

// Obtener nodos disponibles para enrutamiento
func GetAvailableNodes() []string {
	KnownNodesMutex.RLock()
	defer KnownNodesMutex.RUnlock()

	// Excluir este nodo
	availableNodes := make([]string, 0, len(KnownNodes)-1)
	for id := range KnownNodes {
		if id != NodeID {
			availableNodes = append(availableNodes, id)
		}
	}

	return availableNodes
}

// Obtener una ruta para un destino
func GetRouteForDestination(dest string) ([]string, error) {
	KnownRoutesMutex.RLock()
	defer KnownRoutesMutex.RUnlock()

	route, exists := KnownRoutes[dest]
	if !exists {
		return nil, fmt.Errorf("no hay ruta conocida para el destino %s", dest)
	}

	return route, nil
}
