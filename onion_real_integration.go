package main

import (
	"context"
	"log"

	"./onion" // Importar el paquete onion para enrutamiento cebolla real
)

// Inicializar el sistema de enrutamiento cebolla real
func initRealOnionRouting(ctx context.Context) error {
	log.Println("Inicializando sistema de enrutamiento cebolla real...")
	
	// Inicializar el sistema de enrutamiento cebolla real
	if err := onion.InitOnionRouting(ctx, ps); err != nil {
		return err
	}
	
	// Deshabilitar el enrutamiento de cebolla simulado
	disableRoutingHops = true
	
	log.Println("Sistema de enrutamiento cebolla real inicializado correctamente")
	return nil
}

// Publicar un mensaje usando enrutamiento cebolla real
func publishWithRealOnionRouting(msg Message) error {
	return onion.PublishWithRealOnionRouting(p2pTopic, msg)
}
