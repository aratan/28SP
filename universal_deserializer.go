package main

import (
	"encoding/json"
	"fmt"
	"log"
)

// UniversalDeserializeMessage intenta deserializar un mensaje usando varios métodos
// Esta función es muy robusta y puede manejar diferentes formatos de mensajes
func UniversalDeserializeMessage(data []byte, keys [][]byte) (Message, error) {
	// Método 1: Intentar deserializar directamente como JSON
	var msg Message
	err1 := json.Unmarshal(data, &msg)
	if err1 == nil && msg.ID != "" && msg.From.Username != "" {
		log.Printf(Green+"Mensaje deserializado exitosamente usando JSON directo"+Reset)
		return msg, nil
	}

	// Método 2: Intentar descifrar con XOR y luego deserializar
	if len(keys) > 0 {
		// Usar solo la primera clave para simplificar
		key := keys[0]
		
		// Descifrar con XOR
		decrypted := make([]byte, len(data))
		for i := 0; i < len(data); i++ {
			decrypted[i] = data[i] ^ key[i%len(key)]
		}
		
		// Intentar deserializar el resultado
		var msg2 Message
		err2 := json.Unmarshal(decrypted, &msg2)
		if err2 == nil && msg2.ID != "" && msg2.From.Username != "" {
			log.Printf(Green+"Mensaje deserializado exitosamente usando XOR+JSON"+Reset)
			return msg2, nil
		}
	}

	// Método 3: Intentar usar las funciones antiguas de deserialización
	msg3, err3 := deserializeMessage(data, keys)
	if err3 == nil && msg3.ID != "" && msg3.From.Username != "" {
		log.Printf(Green+"Mensaje deserializado exitosamente usando el método antiguo"+Reset)
		return msg3, nil
	}

	// Si llegamos aquí, todos los métodos fallaron
	return Message{}, fmt.Errorf("todos los métodos de deserialización fallaron: %v, %v", err1, err3)
}
