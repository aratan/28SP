# Solución al error "failed to parse multiaddrs: empty multiaddrs"

Este documento proporciona instrucciones para solucionar el error "failed to create host: failed to parse multiaddrs: empty multiaddrs" al ejecutar la aplicación P2P con Docker en Windows 11.

## Causa del problema

El error "failed to parse multiaddrs: empty multiaddrs" indica que la aplicación está intentando crear un host libp2p pero no puede analizar las direcciones multiaddr porque están vacías. Esto puede ocurrir por varias razones:

1. La aplicación no está recibiendo una dirección de escucha válida
2. La configuración no se está cargando correctamente
3. Las variables de entorno necesarias no están definidas

## Soluciones

### Solución 1: Ejecutar con un comando personalizado

```powershell
# Ejecutar un contenedor con un comando personalizado
.\run-with-command.ps1
```

Este script ejecuta un contenedor con un comando personalizado que especifica explícitamente la dirección de escucha.

### Solución 2: Ejecutar con un archivo de configuración JSON

```powershell
# Ejecutar un contenedor con un archivo de configuración JSON
.\run-with-config.ps1
```

Este script crea un archivo de configuración JSON personalizado y ejecuta la aplicación con ese archivo.

### Solución 3: Ejecutar con un archivo de configuración YAML

```powershell
# Ejecutar un contenedor con un archivo de configuración YAML
.\run-with-yaml.ps1
```

Este script crea un archivo de configuración YAML personalizado y ejecuta la aplicación con ese archivo.

### Solución 4: Ejecutar con un archivo de configuración YAML modificado

```powershell
# Ejecutar un contenedor con un archivo de configuración YAML modificado
.\run-with-modified-yaml.ps1
```

Este script modifica el archivo de configuración YAML existente para añadir las direcciones de escucha y ejecuta la aplicación con ese archivo.

### Solución 5: Ejecutar con un archivo de configuración YAML completo

```powershell
# Ejecutar un contenedor con un archivo de configuración YAML completo
.\run-with-complete-yaml.ps1
```

Este script crea un archivo de configuración YAML completo que incluye todas las opciones posibles y ejecuta la aplicación con ese archivo.

## Verificar los logs

Para verificar si la solución ha funcionado, puedes ver los logs del contenedor:

```powershell
docker logs -f p2p-app
```

## Acceder a la interfaz web

Si la aplicación se inicia correctamente, puedes acceder a la interfaz web en:

- http://localhost:8080

## Nota importante

Aunque la aplicación muestra el error "Failed to create host: failed to parse multiaddr: empty multiaddr", parece que sí está iniciando el servidor HTTP en el puerto 8080. Esto significa que puedes acceder a la interfaz web, pero es posible que algunas funcionalidades relacionadas con la comunicación P2P no estén disponibles.

Si necesitas la funcionalidad P2P completa, es posible que necesites modificar el código fuente de la aplicación para que acepte correctamente las direcciones de escucha.
