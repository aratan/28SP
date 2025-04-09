# Guía para probar el enrutamiento cebolla con Docker en Windows 11 (Go 1.22)

Esta guía proporciona instrucciones paso a paso para probar el sistema de enrutamiento cebolla real con Docker en Windows 11, usando Go 1.22.

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

## Opciones para probar el enrutamiento cebolla

### Opción 1: Actualizar el archivo go.mod

Si estás teniendo problemas con la versión de Go, puedes actualizar el archivo go.mod:

```powershell
# Ejecutar el script para actualizar go.mod
.\update-go-mod.ps1
```

### Opción 2: Construir la imagen Docker con Go 1.22

```powershell
# Ejecutar el script para construir la imagen Docker con Go 1.22
.\build-docker-image-go1.22.ps1
```

### Opción 3: Ejecutar un solo nodo

```powershell
# Ejecutar el script para un solo nodo
.\run-single-node-linux.ps1
```

### Opción 4: Ejecutar múltiples nodos con Docker Compose (recomendado)

```powershell
# Ejecutar el script para Docker Compose
.\run-docker-compose-linux.ps1
```

## Verificar el funcionamiento

### Ver los logs

```powershell
# Para un solo nodo
docker logs -f p2p-node1

# Para múltiples nodos con Docker Compose
docker-compose -f docker-compose-windows.yml logs -f
```

### Acceder a las interfaces web

- Nodo 1: http://localhost:8081
- Nodo 2: http://localhost:8082
- Nodo 3: http://localhost:8083
- Nodo 4: http://localhost:8084
- Nodo 5: http://localhost:8085

## Detener los nodos

```powershell
# Para un solo nodo
docker stop p2p-node1
docker rm p2p-node1

# Para múltiples nodos con Docker Compose
docker-compose -f docker-compose-windows.yml down
```

## Solución de problemas

### Problema: Error con la versión de Go

Si recibes un error como "invalid go version '1.22.0': must match format 1.23", significa que la imagen de Docker que estás usando no es compatible con la versión de Go especificada en el archivo go.mod.

Soluciones:
1. Actualizar el archivo go.mod para usar una versión de Go compatible con la imagen de Docker:
   ```powershell
   .\update-go-mod.ps1
   ```

2. Usar una imagen de Docker con una versión más reciente de Go:
   ```powershell
   .\build-docker-image-go1.22.ps1
   ```

### Problema: Docker no está en ejecución

Si recibes errores de conexión con Docker:

1. Verifica que Docker Desktop esté en ejecución (el icono en la bandeja del sistema debe estar verde)
2. Si Docker Desktop está en ejecución pero sigues recibiendo errores, reinicia Docker Desktop

### Problema: Error al montar volúmenes

Si recibes errores relacionados con el montaje de volúmenes:

1. Asegúrate de que Docker Desktop tenga acceso a la unidad donde está tu proyecto
   - Abre Docker Desktop
   - Ve a Configuración > Recursos > Integración de WSL
   - Asegúrate de que la unidad donde está tu proyecto esté compartida
