# Prueba del Enrutamiento Cebolla Real

Este documento proporciona instrucciones detalladas para probar el sistema de enrutamiento cebolla real con múltiples nodos usando Docker.

## Requisitos

- Docker
- Docker Compose
- Bash (para ejecutar los scripts)

## Estructura de archivos

- `onion/`: Directorio con la implementación modular del enrutamiento cebolla
  - `types.go`: Definición de tipos y variables globales
  - `crypto.go`: Funciones de cifrado y gestión de claves
  - `control.go`: Implementación del topic de control
  - `routing.go`: Implementación del enrutamiento cebolla
  - `init.go`: Funciones de inicialización
- `onion_integration.go`: Integración con el código existente
- `Dockerfile`: Configuración para construir la imagen Docker
- `docker-compose.yml`: Configuración para ejecutar múltiples nodos
- `config-node*.yaml`: Archivos de configuración para cada nodo
- `docker-test.sh`: Script para ejecutar la prueba con Docker
- `docker-cleanup.sh`: Script para limpiar los contenedores y redes Docker

## Pasos para probar el enrutamiento cebolla

### 1. Compilar el código

```bash
go build -o p2p-app .
```

### 2. Ejecutar la prueba con Docker

```bash
# Dar permisos de ejecución a los scripts
chmod +x docker-test.sh docker-cleanup.sh

# Ejecutar la prueba
./docker-test.sh
```

Esto creará 5 nodos Docker que se comunicarán entre sí a través de la red P2P.

### 3. Verificar los logs

```bash
# Ver los logs de un nodo específico
docker logs -f p2p-node1
```

Busca mensajes como:
- "Sistema de enrutamiento cebolla real inicializado correctamente"
- "Nodo anunciado en la red"
- "Mensaje enviado con enrutamiento cebolla real"
- "Mensaje reenviado al nodo X"

### 4. Probar el envío de mensajes

Puedes enviar mensajes a través de la interfaz web de cualquier nodo:

- Nodo 1: http://localhost:8081
- Nodo 2: http://localhost:8082
- Nodo 3: http://localhost:8083
- Nodo 4: http://localhost:8084
- Nodo 5: http://localhost:8085

### 5. Limpiar después de la prueba

```bash
./docker-cleanup.sh
```

## Verificación del enrutamiento cebolla

Para verificar que el enrutamiento cebolla está funcionando correctamente, puedes observar los siguientes indicadores en los logs:

1. **Anuncio de nodos**: Cada nodo debe anunciar su presencia y registrar otros nodos.
   ```
   Nodo anunciado en la red: [ID]
   Nodo registrado: [ID]
   ```

2. **Selección de rutas**: Al enviar un mensaje, se debe seleccionar una ruta aleatoria.
   ```
   Ruta seleccionada: [nodo1, nodo2, nodo3]
   ```

3. **Cifrado por capas**: El mensaje debe cifrarse con múltiples capas.
   ```
   Mensaje enviado con enrutamiento cebolla real a través de [N] nodos
   ```

4. **Procesamiento en nodos intermedios**: Cada nodo en la ruta debe procesar su capa y reenviar el mensaje.
   ```
   Mensaje reenviado al nodo [ID]
   ```

5. **Recepción en el destino final**: El nodo de destino debe recibir y procesar el mensaje original.
   ```
   Mensaje final recibido
   ```

## Solución de problemas

### Problema: Los nodos no se encuentran entre sí

Verifica que todos los nodos estén en la misma red Docker y que el servicio mDNS esté habilitado en la configuración.

### Problema: Errores de cifrado

Verifica que las claves RSA se estén generando y distribuyendo correctamente. Los logs deben mostrar mensajes como "Sistema de claves inicializado" y "Nodo registrado".

### Problema: Mensajes no entregados

Verifica que la ruta seleccionada sea válida y que todos los nodos en la ruta estén activos. Los logs deben mostrar la ruta seleccionada y los mensajes de reenvío.
