package main

import (
	"log"
	"sync"
	"time"
)

// Variables globales para la protección contra inundación
var (
	// Mapa para almacenar los mensajes recientes por usuario
	userMessageTimes = make(map[string][]time.Time)
	// Mapa para detectar mensajes duplicados
	messageCache = make(map[string]bool)
	// Mutex para proteger el acceso a los mapas
	floodMutex = &sync.RWMutex{}
	// Configuración
	maxMsgsPerMinute = 10
)

// Iniciar la limpieza periódica del caché de mensajes
func startFloodProtection() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			cleanupMessageCache()
		}
	}()
}

// Limpiar el caché de mensajes antiguos
func cleanupMessageCache() {
	floodMutex.Lock()
	defer floodMutex.Unlock()
	
	// Limpiar mensajes antiguos (más de 30 minutos)
	cutoff := time.Now().Add(-30 * time.Minute)
	
	// Limpiar tiempos de mensajes por usuario
	for userID, times := range userMessageTimes {
		var newTimes []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				newTimes = append(newTimes, t)
			}
		}
		
		if len(newTimes) > 0 {
			userMessageTimes[userID] = newTimes
		} else {
			delete(userMessageTimes, userID)
		}
	}
	
	// Reiniciar el caché de mensajes duplicados cada 30 minutos
	// Esto es una simplificación, en un sistema real podríamos usar un TTL por mensaje
	messageCache = make(map[string]bool)
	
	log.Printf("Limpieza de caché de mensajes completada. Usuarios activos: %d", len(userMessageTimes))
}

// Verificar si un mensaje debe ser permitido
func shouldAllowMessage(userID string, messageID string) bool {
	floodMutex.Lock()
	defer floodMutex.Unlock()
	
	// 1. Verificar si el mensaje es un duplicado
	if _, exists := messageCache[messageID]; exists {
		log.Printf("Mensaje duplicado detectado de %s: %s", userID, messageID)
		return false
	}
	
	// 2. Verificar límite de tasa
	now := time.Now()
	times := userMessageTimes[userID]
	
	// Filtrar mensajes del último minuto
	var recentMessages []time.Time
	oneMinuteAgo := now.Add(-1 * time.Minute)
	
	for _, t := range times {
		if t.After(oneMinuteAgo) {
			recentMessages = append(recentMessages, t)
		}
	}
	
	// Verificar si excede el límite
	if len(recentMessages) >= maxMsgsPerMinute {
		log.Printf("Usuario %s excedió el límite de mensajes por minuto (%d)", 
			userID, maxMsgsPerMinute)
		return false
	}
	
	// Actualizar el registro de mensajes
	userMessageTimes[userID] = append(recentMessages, now)
	messageCache[messageID] = true
	
	return true
}
