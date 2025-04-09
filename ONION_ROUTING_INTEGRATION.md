# Integración del Enrutamiento Cebolla Real

Este documento proporciona instrucciones para integrar el enrutamiento cebolla real con el código principal.

## Estructura del Enrutamiento Cebolla Real

El enrutamiento cebolla real está implementado en el paquete `onion`, que contiene los siguientes archivos:

- `onion/types.go`: Definición de tipos y variables globales
- `onion/crypto.go`: Funciones de cifrado y gestión de claves
- `onion/control.go`: Implementación del topic de control
- `onion/routing.go`: Implementación del enrutamiento cebolla
- `onion/init.go`: Funciones de inicialización

## Pasos para la Integración

### 1. Importar el paquete `onion` en `main.go`

Añadir la siguiente línea a las importaciones en `main.go`:

```go
import (
    // ...
    "./onion" // Importar el paquete onion para enrutamiento cebolla real
)
```

### 2. Crear una función para inicializar el enrutamiento cebolla real

Añadir la siguiente función a `main.go` o a un archivo separado:

```go
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
```

### 3. Crear una función para publicar mensajes con enrutamiento cebolla real

Añadir la siguiente función a `main.go` o a un archivo separado:

```go
// Publicar un mensaje usando enrutamiento cebolla real
func publishWithRealOnionRouting(msg Message) error {
    return onion.PublishWithRealOnionRouting(p2pTopic, msg)
}
```

### 4. Modificar la función `publishToP2P` para usar el enrutamiento cebolla real

Modificar la función `publishToP2P` para usar el enrutamiento cebolla real:

```go
func publishToP2P(msg Message) {
    // Asegurarse de que el mensaje tenga un ID
    if msg.ID == "" {
        msg.ID = generateMessageID()
    }

    log.Printf("Publicando mensaje ID: %s a P2P. Destino: %s", msg.ID, msg.To)

    // Asegurarse de que el mensaje tenga información del remitente
    if msg.From.Username == "" {
        config, _ := readConfig()
        if config != nil && len(config.Users) > 0 {
            msg.From.Username = config.Users[0].Username
        } else {
            msg.From.Username = "anonymous"
        }
    }

    log.Printf("Remitente del mensaje: %s", msg.From.Username)

    // Aplicar opciones de seguridad al mensaje
    SecureMessageFix(&msg, securityConfig)

    log.Printf("Mensaje preparado con seguridad. Encrypted: %v, AnonymousSender: %v",
        msg.Encrypted, msg.AnonymousSender)

    // Verificar si debemos usar enrutamiento cebolla real
    if securityConfig.OnionRouting && !disableRoutingHops {
        // Usar el sistema de enrutamiento cebolla real
        log.Printf("Usando enrutamiento cebolla real para el mensaje ID: %s", msg.ID)
        if err := publishWithRealOnionRouting(msg); err != nil {
            log.Printf("Error en enrutamiento cebolla real: %v. Usando método tradicional.", err)
            // Fallback al método tradicional
            publishWithTraditionalMethod(msg)
        } else {
            log.Printf("Mensaje publicado exitosamente con enrutamiento cebolla real. ID: %s", msg.ID)
        }
    } else {
        // Usar el método tradicional
        publishWithTraditionalMethod(msg)
    }
}
```

### 5. Modificar la función `handleP2PMessages` para procesar mensajes de enrutamiento cebolla

Modificar la función `handleP2PMessages` para procesar mensajes de enrutamiento cebolla:

```go
func handleP2PMessages(ctx context.Context) {
    log.Printf("Iniciando manejador de mensajes P2P...")
    for {
        log.Printf("Esperando mensajes P2P...")
        m, err := p2pSub.Next(ctx)
        if err != nil {
            log.Printf("Failed to get next message: %v", err)
            continue
        }
        // Log the message data size before deserialization
        log.Printf("Received message from %s, data size: %d bytes", m.ReceivedFrom, len(m.Message.Data))

        // Intentar decodificar como mensaje de enrutamiento cebolla
        var onionMsg map[string]interface{}
        if err := json.Unmarshal(m.Message.Data, &onionMsg); err == nil {
            msgType, ok := onionMsg["type"].(string)
            if ok && msgType == "onion" {
                // Es un mensaje de enrutamiento cebolla
                currentHop, ok := onionMsg["currentHop"].(string)
                if ok && currentHop == onion.NodeID {
                    // Este mensaje es para este nodo
                    if err := onion.ProcessOnionMessage(m.Message.Data); err != nil {
                        log.Printf("Error al procesar mensaje de enrutamiento cebolla: %v", err)
                    }
                    continue
                }
            }
        }
        
        // Intentar decodificar como mensaje de control
        var controlMsg map[string]interface{}
        if err := json.Unmarshal(m.Message.Data, &controlMsg); err == nil {
            msgType, ok := controlMsg["type"].(string)
            if ok {
                switch msgType {
                case onion.MsgTypeNodeAnnouncement, onion.MsgTypeKeyExchange, onion.MsgTypeRouteUpdate, onion.MsgTypeNetworkStatus:
                    // Es un mensaje de control
                    onion.ProcessControlMessage(m.Message.Data)
                    continue
                }
            }
        }
        
        // Si no es un mensaje de enrutamiento cebolla ni de control, usar el deserializador seguro tradicional
        msg, err := SecureDeserializeMessageFix(m.Message.Data, p2pKeys)
        if err != nil {
            log.Printf("Error al deserializar mensaje: %v", err)
            continue
        }
        
        // Procesar como mensaje normal
        processP2PMessage(msg)
    }
}
```

### 6. Inicializar el enrutamiento cebolla real en la función `main`

Añadir el siguiente código a la función `main` después de inicializar pubsub:

```go
// Inicializar el sistema de enrutamiento cebolla real
if err := initRealOnionRouting(ctx); err != nil {
    log.Printf(Red+"Error al inicializar el sistema de enrutamiento cebolla real: %v"+Reset, err)
    log.Printf(Yellow+"Usando enrutamiento cebolla simulado como fallback"+Reset)
} else {
    log.Printf(Green+"Sistema de enrutamiento cebolla real inicializado correctamente"+Reset)
}
```

## Verificación

Para verificar que el enrutamiento cebolla real está funcionando correctamente, puedes buscar los siguientes mensajes en los logs:

- "Sistema de enrutamiento cebolla real inicializado correctamente"
- "Nodo anunciado en la red"
- "Mensaje enviado con enrutamiento cebolla real"
- "Mensaje reenviado al nodo X"

## Solución de problemas

Si encuentras problemas con el enrutamiento cebolla real, puedes:

1. Verificar que el paquete `onion` esté correctamente importado
2. Verificar que la función `initRealOnionRouting` se esté llamando correctamente
3. Verificar que la variable `disableRoutingHops` esté establecida en `true`
4. Verificar que la función `publishWithRealOnionRouting` se esté llamando correctamente
5. Verificar que la función `handleP2PMessages` esté procesando correctamente los mensajes de enrutamiento cebolla
