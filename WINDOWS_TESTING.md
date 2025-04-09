# Prueba del Enrutamiento Cebolla en Windows 11

Este documento proporciona instrucciones detalladas para probar el sistema de enrutamiento cebolla real con múltiples nodos usando Docker en Windows 11.

## Requisitos

- Windows 11
- Docker Desktop para Windows
- PowerShell

## Preparación

1. Asegúrate de que Docker Desktop esté instalado y en ejecución.
2. Asegúrate de que Docker esté configurado para usar contenedores Windows (no Linux).
   - Haz clic derecho en el icono de Docker en la bandeja del sistema
   - Selecciona "Switch to Windows containers..." si actualmente está usando contenedores Linux

## Pasos para probar el enrutamiento cebolla

### 1. Abrir PowerShell como administrador

Busca "PowerShell" en el menú de inicio, haz clic derecho y selecciona "Ejecutar como administrador".

### 2. Navegar al directorio del proyecto

```powershell
cd C:\ruta\al\proyecto
```

### 3. Ejecutar el script de prueba

```powershell
# Permitir la ejecución de scripts (si es necesario)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Ejecutar el script de prueba
.\docker-test-windows.ps1
```

Esto creará 5 nodos Docker que se comunicarán entre sí a través de la red P2P.

### 4. Verificar los logs

```powershell
# Ver los logs de un nodo específico
docker logs -f p2p-node1
```

Busca mensajes como:
- "Sistema de enrutamiento cebolla real inicializado correctamente"
- "Nodo anunciado en la red"
- "Mensaje enviado con enrutamiento cebolla real"
- "Mensaje reenviado al nodo X"

### 5. Probar el envío de mensajes

Puedes enviar mensajes a través de la interfaz web de cualquier nodo:

- Nodo 1: http://localhost:8081
- Nodo 2: http://localhost:8082
- Nodo 3: http://localhost:8083
- Nodo 4: http://localhost:8084
- Nodo 5: http://localhost:8085

### 6. Limpiar después de la prueba

```powershell
.\docker-cleanup-windows.ps1
```

## Solución de problemas

### Problema: Error al construir la imagen Docker

Si recibes un error al construir la imagen Docker, asegúrate de que Docker esté configurado para usar contenedores Windows:

```powershell
# Verificar la configuración de Docker
docker info | Select-String "OSType"
```

Debería mostrar "OSType: windows". Si muestra "OSType: linux", cambia a contenedores Windows:

```powershell
# Cambiar a contenedores Windows desde PowerShell
& 'C:\Program Files\Docker\Docker\DockerCli.exe' -SwitchDaemon
```

### Problema: Error al montar volúmenes

Si recibes un error relacionado con el montaje de volúmenes, asegúrate de que la ruta sea correcta y que Docker tenga permisos para acceder a ella:

```powershell
# Verificar que el directorio existe
Test-Path "C:\ruta\al\proyecto\node1"

# Crear el directorio si no existe
New-Item -ItemType Directory -Path "C:\ruta\al\proyecto\node1" -Force
```

### Problema: Los nodos no se comunican entre sí

Asegúrate de que todos los nodos estén en la misma red Docker:

```powershell
# Verificar la red Docker
docker network inspect p2p-network
```

Deberías ver los 5 nodos conectados a la red.
