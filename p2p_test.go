package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
)

// TestP2PConnection es una función para probar la conexión P2P entre dos nodos
// Ejecuta esta función con: go test -run TestP2PConnection
func TestP2PConnection(t *testing.T) {
	// Configuración para pruebas
	listenAddr := "/ip4/0.0.0.0/tcp/9001"
	topicName := "test-topic"

	// Configurar para usar NOISE en lugar de TLS
	security := libp2p.Security(noise.ID, noise.New)

	// Crear host libp2p
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
		libp2p.NATPortMap(),
		security,
	)
	if err != nil {
		log.Fatalf("Error al crear host libp2p: %v", err)
	}

	// Mostrar información del nodo
	log.Printf("ID del nodo: %s", h.ID())
	log.Printf("Direcciones del nodo:")
	for _, addr := range h.Addrs() {
		log.Printf("  %s/p2p/%s", addr, h.ID())
	}

	// Crear contexto
	ctx := context.Background()

	// Configurar descubrimiento mDNS
	err = setupTestMDNS(ctx, h, "test-p2p")
	if err != nil {
		log.Fatalf("Error al configurar mDNS: %v", err)
	}

	// Crear pubsub
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		log.Fatalf("Error al crear pubsub: %v", err)
	}

	// Suscribirse al topic
	topic, err := ps.Join(topicName)
	if err != nil {
		log.Fatalf("Error al unirse al topic: %v", err)
	}

	// Suscribirse para recibir mensajes
	sub, err := topic.Subscribe()
	if err != nil {
		log.Fatalf("Error al suscribirse al topic: %v", err)
	}

	// Iniciar goroutine para recibir mensajes
	go handleTestMessages(ctx, sub)

	// Enviar mensajes de prueba cada 5 segundos
	go func() {
		for i := 0; i < 10; i++ {
			time.Sleep(5 * time.Second)

			// Crear mensaje de prueba
			msg := Message{
				ID:      fmt.Sprintf("test-msg-%d", i),
				From:    UserInfo{Username: "test-user", PeerID: h.ID().String()},
				To:      "broadcast",
				Content: Content{Title: "Test Message", Message: fmt.Sprintf("Hello world %d", i)},
			}

			// Serializar mensaje
			msgBytes, err := json.Marshal(msg)
			if err != nil {
				log.Printf("Error al serializar mensaje: %v", err)
				continue
			}

			// Publicar mensaje
			err = topic.Publish(ctx, msgBytes)
			if err != nil {
				log.Printf("Error al publicar mensaje: %v", err)
				continue
			}

			log.Printf("Mensaje enviado: %s", msg.ID)
		}
	}()

	// Esperar para mantener el programa en ejecución
	select {}
}

// Función para manejar mensajes recibidos
func handleTestMessages(ctx context.Context, sub *pubsub.Subscription) {
	for {
		m, err := sub.Next(ctx)
		if err != nil {
			log.Printf("Error al recibir mensaje: %v", err)
			continue
		}

		log.Printf("Mensaje recibido de %s, tamaño: %d bytes", m.ReceivedFrom, len(m.Data))

		// Deserializar mensaje
		var msg Message
		err = json.Unmarshal(m.Data, &msg)
		if err != nil {
			log.Printf("Error al deserializar mensaje: %v", err)
			continue
		}

		log.Printf("Mensaje deserializado: ID=%s, From=%s, Title=%s",
			msg.ID, msg.From.Username, msg.Content.Title)
	}
}

// Configurar mDNS para descubrimiento de peers
func setupTestMDNS(ctx context.Context, h host.Host, serviceTag string) error {
	service := mdns.NewMdnsService(h, serviceTag, &testMdnsNotifee{h: h})
	return service.Start()
}

// Notificador para mDNS
type testMdnsNotifee struct {
	h host.Host
}

// HandlePeerFound se llama cuando se encuentra un peer mediante mDNS
func (n *testMdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.h.ID() {
		return // Ignorar a sí mismo
	}

	log.Printf("Peer encontrado: %s", pi.ID)

	// Conectar al peer
	err := n.h.Connect(context.Background(), pi)
	if err != nil {
		log.Printf("Error al conectar con peer %s: %v", pi.ID, err)
		return
	}

	log.Printf("Conectado exitosamente al peer: %s", pi.ID)
}
