# Guía final para probar la aplicación P2P con Docker en Windows 11

Esta guía proporciona instrucciones paso a paso para probar la aplicación P2P con Docker en Windows 11.

## Requisitos

- Windows 11
- Docker Desktop para Windows
- PowerShell

## Preparación

1. **Instalar Docker Desktop**:
   - Descarga e instala Docker Desktop desde [Docker Hub](https://www.docker.com/products/docker-desktop)
   - Inicia Docker Desktop desde el menú de inicio
   - Espera a que Docker Desktop se inicie completamente (el icono en la bandeja del sistema se volverá verde)

2. **Verificar la instalación de Docker**:
   - Abre PowerShell y ejecuta:
   ```powershell
   docker version
   ```
   - Deberías ver información sobre la versión del cliente y del servidor

## Construir la imagen Docker

Debido a los errores en los archivos de enrutamiento cebolla, vamos a construir la imagen Docker con solo los archivos principales:

```powershell
# Ejecutar el script para construir la imagen Docker con solo los archivos principales
.\build-docker-main-only.ps1
```

Este script construirá la imagen Docker usando solo los archivos principales (`main.go` y `flood_protection.go`), sin incluir los archivos de enrutamiento cebolla que tienen errores.

## Ejecutar la aplicación

### Opción 1: Ejecutar un solo contenedor

```powershell
# Ejecutar el script para un solo contenedor
.\run-docker-tidy.ps1
```

### Opción 2: Ejecutar múltiples contenedores (recomendado)

```powershell
# Ejecutar el script para múltiples contenedores
.\run-multiple-nodes-tidy.ps1
```

### Opción 3: Ejecutar con Docker Compose

```powershell
# Ejecutar el script para Docker Compose
.\run-docker-compose-simple.ps1
```

## Verificar el funcionamiento

### Ver los logs

```powershell
# Para un solo contenedor
docker logs -f p2p-app

# Para múltiples contenedores
docker logs -f p2p-node1
docker logs -f p2p-node2
docker logs -f p2p-node3
docker logs -f p2p-node4
docker logs -f p2p-node5

# Para Docker Compose
docker-compose -f docker-compose-simple.yml logs -f
```

### Acceder a las interfaces web

- Un solo contenedor: http://localhost:8080
- Múltiples contenedores:
  - Nodo 1: http://localhost:8081
  - Nodo 2: http://localhost:8082
  - Nodo 3: http://localhost:8083
  - Nodo 4: http://localhost:8084
  - Nodo 5: http://localhost:8085

## Detener los contenedores

```powershell
# Para un solo contenedor
docker stop p2p-app
docker rm p2p-app

# Para múltiples contenedores
.\stop-multiple-nodes.ps1

# Para Docker Compose
.\stop-docker-compose-simple.ps1
```

## Solución de problemas

### Problema: Docker no está en ejecución

Si recibes errores de conexión con Docker:

1. Verifica que Docker Desktop esté en ejecución (el icono en la bandeja del sistema debe estar verde)
2. Si Docker Desktop está en ejecución pero sigues recibiendo errores, reinicia Docker Desktop

### Problema: Puertos en uso

Si recibes errores de que los puertos ya están en uso:

1. Verifica qué proceso está usando el puerto:
   ```powershell
   netstat -ano | findstr :808
   ```

2. Detén el proceso o cambia los puertos en el script:
   ```powershell
   -p "909$i:8080"
   ```
