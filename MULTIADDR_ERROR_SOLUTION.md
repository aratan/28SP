# Solución al error "failed to parse multiaddrs: empty multiaddrs"

Este documento proporciona instrucciones para solucionar el error "failed to create host: failed to parse multiaddrs: empty multiaddrs" al ejecutar la aplicación P2P con Docker en Windows 11.

## Causa del problema

El error "failed to parse multiaddrs: empty multiaddrs" indica que la aplicación está intentando crear un host libp2p pero no puede analizar las direcciones multiaddr porque están vacías. Esto puede ocurrir por varias razones:

1. La aplicación no está recibiendo una dirección de escucha válida
2. La configuración no se está cargando correctamente
3. Las variables de entorno necesarias no están definidas

## Soluciones

### Solución 1: Construir una imagen Docker con configuración fija

```powershell
# Construir la imagen Docker con configuración fija
.\build-docker-fixed.ps1
```

Esta imagen Docker incluye una configuración predeterminada con una dirección de escucha explícita y ejecuta la aplicación con argumentos explícitos.

### Solución 2: Ejecutar con variables de entorno adicionales

```powershell
# Ejecutar un contenedor con variables de entorno adicionales
.\run-with-env.ps1
```

Este script ejecuta un contenedor con variables de entorno adicionales que especifican las direcciones de escucha para la aplicación.

### Solución 3: Ejecutar múltiples contenedores con variables de entorno adicionales

```powershell
# Ejecutar múltiples contenedores con variables de entorno adicionales
.\run-multiple-with-env.ps1
```

Este script ejecuta múltiples contenedores con variables de entorno adicionales que especifican las direcciones de escucha para la aplicación.

### Solución 4: Ejecutar con un comando personalizado

```powershell
# Ejecutar un contenedor con un comando personalizado
.\run-with-command.ps1
```

Este script ejecuta un contenedor con un comando personalizado que especifica explícitamente la dirección de escucha.

## Verificar los logs

Para verificar si la solución ha funcionado, puedes ver los logs del contenedor:

```powershell
docker logs -f p2p-app
```

o para múltiples contenedores:

```powershell
docker logs -f p2p-node1
docker logs -f p2p-node2
docker logs -f p2p-node3
docker logs -f p2p-node4
docker logs -f p2p-node5
```

## Acceder a la interfaz web

Si la aplicación se inicia correctamente, puedes acceder a la interfaz web en:

- Un solo contenedor: http://localhost:8080
- Múltiples contenedores:
  - Nodo 1: http://localhost:8081
  - Nodo 2: http://localhost:8082
  - Nodo 3: http://localhost:8083
  - Nodo 4: http://localhost:8084
  - Nodo 5: http://localhost:8085
