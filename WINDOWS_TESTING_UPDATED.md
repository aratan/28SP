# Prueba del Enrutamiento Cebolla en Windows 11

Este documento proporciona instrucciones detalladas para probar el sistema de enrutamiento cebolla real con múltiples nodos usando Docker en Windows 11.

## Requisitos

- Windows 11
- Docker Desktop para Windows
- WSL 2 (Windows Subsystem for Linux 2)
- PowerShell

## Preparación

1. Asegúrate de que Docker Desktop esté instalado y en ejecución.
   - Puedes descargarlo desde [Docker Hub](https://www.docker.com/products/docker-desktop)
   - Después de instalarlo, inicia Docker Desktop desde el menú de inicio

2. Asegúrate de que WSL 2 esté habilitado.
   - Abre PowerShell como administrador y ejecuta:
   ```powershell
   wsl --status
   ```
   - Si WSL 2 no está habilitado, sigue las instrucciones en [Instalación de WSL](https://docs.microsoft.com/es-es/windows/wsl/install)

## Diagnóstico de Docker

Antes de ejecutar las pruebas, es recomendable verificar que Docker esté funcionando correctamente:

```powershell
# Ejecutar el script de diagnóstico
.\docker-diagnose.ps1
```

Este script verificará:
- Si Docker está instalado y en ejecución
- La versión de Docker
- El tipo de contenedores (Linux o Windows)
- Si WSL 2 está habilitado
- La conectividad de red de Docker
- Si se puede ejecutar un contenedor de prueba

## Pasos para probar el enrutamiento cebolla

### 1. Abrir PowerShell

Busca "PowerShell" en el menú de inicio y ábrelo.

### 2. Navegar al directorio del proyecto

```powershell
cd C:\ruta\al\proyecto
```

### 3. Ejecutar el script de prueba

```powershell
# Permitir la ejecución de scripts (si es necesario)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Ejecutar el script de prueba para WSL 2
.\docker-test-wsl.ps1
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

### Problema: Docker no está en ejecución

Si recibes el error "error during connect: Head "http://%2F%2F.%2Fpipe%2FdockerDesktopLinuxEngine/_ping": open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified", significa que Docker Desktop no está en ejecución:

1. Busca "Docker Desktop" en el menú de inicio y ábrelo
2. Espera a que Docker Desktop se inicie completamente (el icono en la bandeja del sistema se volverá verde)
3. Intenta ejecutar el script de prueba nuevamente

### Problema: WSL 2 no está habilitado

Si Docker Desktop requiere WSL 2 pero no está habilitado:

1. Abre PowerShell como administrador
2. Ejecuta:
   ```powershell
   wsl --install
   ```
3. Reinicia tu computadora
4. Inicia Docker Desktop y verifica que esté configurado para usar WSL 2

### Problema: Permisos de volumen

Si recibes errores relacionados con el montaje de volúmenes:

1. Asegúrate de que Docker Desktop tenga acceso a la unidad donde está tu proyecto
   - Abre Docker Desktop
   - Ve a Configuración > Recursos > Integración de WSL
   - Asegúrate de que la unidad donde está tu proyecto esté compartida

2. Usa rutas absolutas en lugar de relativas:
   ```powershell
   -v "C:\ruta\completa\al\proyecto\node$i:/app/data"
   ```

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
