# Guía de solución de problemas para Docker en Windows 11

Esta guía proporciona instrucciones para solucionar problemas al ejecutar la aplicación P2P con Docker en Windows 11.

## Verificar el estado de los contenedores

Si los contenedores se están cerrando inmediatamente después de iniciarlos, puedes verificar los logs para entender qué está sucediendo:

```powershell
# Verificar el estado de los contenedores
docker ps -a

# Verificar los logs de un contenedor específico
docker logs p2p-node1
```

## Probar con una imagen base diferente

Si la imagen Alpine está causando problemas, puedes probar con una imagen basada en Debian:

```powershell
# Construir la imagen Docker con Debian
.\build-docker-debian.ps1
```

## Ejecutar en modo interactivo

Para ver los errores en tiempo real, puedes ejecutar un contenedor en modo interactivo:

```powershell
# Ejecutar un contenedor en modo interactivo
.\run-interactive.ps1
```

## Verificar la configuración

Para verificar que la configuración dentro del contenedor es correcta:

```powershell
# Verificar la configuración dentro del contenedor
.\check-config.ps1
```

## Problemas comunes y soluciones

### Problema: Los contenedores se cierran inmediatamente

Posibles causas:
1. La aplicación está encontrando un error al iniciar
2. Falta algún archivo de configuración
3. Hay un problema con los permisos

Soluciones:
1. Verificar los logs del contenedor
2. Ejecutar en modo interactivo para ver los errores en tiempo real
3. Verificar que la configuración es correcta

### Problema: No se puede acceder a la interfaz web

Posibles causas:
1. La aplicación no está escuchando en el puerto correcto
2. Hay un problema con el mapeo de puertos
3. La aplicación no está iniciando correctamente

Soluciones:
1. Verificar que la aplicación está escuchando en el puerto 8080 dentro del contenedor
2. Verificar que el mapeo de puertos es correcto
3. Verificar los logs para ver si hay errores al iniciar

### Problema: Los nodos no pueden comunicarse entre sí

Posibles causas:
1. Los nodos no están en la misma red Docker
2. Hay un problema con la configuración de red
3. La aplicación no está configurada para usar la red Docker

Soluciones:
1. Verificar que todos los nodos están en la misma red Docker
2. Usar IPs estáticas para los nodos
3. Configurar la aplicación para usar la red Docker
