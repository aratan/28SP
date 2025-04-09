# Integración del Enrutamiento Cebolla Real (Versión Corregida)

Este documento proporciona instrucciones para integrar el enrutamiento cebolla real con el código principal, evitando problemas de redeclaración y duplicación de código.

## Archivos Creados

1. **shared_types.go**: Define tipos y variables compartidos entre el código principal y el paquete onion.
2. **onion/shared.go**: Define tipos y variables específicos del paquete onion.
3. **onion_integration_fixed.go**: Proporciona funciones para integrar el enrutamiento cebolla real con el código principal.
4. **utils.go**: Proporciona funciones de utilidad comunes.
5. **main_integration.go**: Muestra cómo usar el enrutamiento cebolla real en el código principal.

## Pasos para la Integración

### 1. Incluir los archivos en tu proyecto

Asegúrate de incluir todos los archivos creados en tu proyecto:

```
shared_types.go
onion/shared.go
onion_integration_fixed.go
utils.go
main_integration.go
```

### 2. Modificar tu función main para usar el enrutamiento cebolla real

En tu función `main`, después de inicializar pubsub, añade el siguiente código:

```go
// Inicializar y usar el enrutamiento cebolla real
InitializeAndUseOnionRouting(ctx, ps, p2pTopic, p2pSub)
```

### 3. Usar las funciones de envío de mensajes con enrutamiento cebolla real

En lugar de usar directamente `publishToP2P`, usa la función `SendMessage` que utiliza el enrutamiento cebolla real:

```go
// Crear un mensaje
msg := Message{
    ID: GenerateMessageID(),
    From: UserInfo{
        Username: "user1",
    },
    To:        "all",
    TablonID:  "tablon1",
    Content: Content{
        Title:   "Título del mensaje",
        Message: "Contenido del mensaje",
    },
    Timestamp: time.Now().Unix(),
}

// Enviar el mensaje con enrutamiento cebolla real
SendMessage(msg)
```

## Verificación

Para verificar que el enrutamiento cebolla real está funcionando correctamente, puedes buscar los siguientes mensajes en los logs:

- "Sistema de enrutamiento cebolla real inicializado correctamente"
- "Nodo anunciado en la red"
- "Mensaje enviado con enrutamiento cebolla real"
- "Mensaje reenviado al nodo X"

## Solución de problemas

Si encuentras problemas con el enrutamiento cebolla real, puedes:

1. Verificar que todos los archivos estén correctamente incluidos en tu proyecto
2. Verificar que la función `InitializeAndUseOnionRouting` se esté llamando correctamente
3. Verificar que la variable `DisableRoutingHops` esté establecida en `true`
4. Verificar que la función `SendMessage` se esté llamando correctamente
5. Verificar que la función `HandleP2PMessages` esté procesando correctamente los mensajes de enrutamiento cebolla

## Notas Importantes

1. **Evitar redeclaraciones**: Los archivos creados están diseñados para evitar redeclaraciones de funciones y variables. Si encuentras errores de redeclaración, asegúrate de no estar importando o definiendo las mismas funciones o variables en múltiples lugares.

2. **Importaciones relativas**: El uso de importaciones relativas como `"./onion"` puede causar problemas en modo módulo de Go. Si encuentras problemas, considera usar importaciones absolutas basadas en el nombre del módulo.

3. **Código duplicado**: Los archivos creados están diseñados para evitar la duplicación de código. Si encuentras código duplicado, considera refactorizar para eliminar la duplicación.

4. **Compatibilidad**: Los archivos creados están diseñados para ser compatibles con el código existente. Si encuentras problemas de compatibilidad, considera adaptar los archivos a tu código específico.
