# Instrucciones para compilar y ejecutar el código

Este documento proporciona instrucciones para compilar y ejecutar el código con enrutamiento cebolla real.

## Compilar el código

Para compilar el código, puedes usar uno de los siguientes métodos:

### Método 1: Usar el script de compilación

```powershell
.\compile_only.ps1
```

Este script compilará el código sin ejecutarlo.

### Método 2: Compilar manualmente

```powershell
go build
```

## Ejecutar el código

Para ejecutar el código, puedes usar uno de los siguientes métodos:

### Método 1: Usar el script de compilación y ejecución

```powershell
.\compile_and_run.ps1
```

Este script compilará y ejecutará el código.

### Método 2: Ejecutar manualmente

```powershell
.\api-p2p-front.exe
```

## Solución de problemas

Si encuentras problemas al compilar o ejecutar el código, aquí hay algunas soluciones comunes:

### Problema: Error "undefined: initRealOnionRouting"

Este error ocurre cuando la función `initRealOnionRouting` no está definida. Para solucionarlo, asegúrate de que el archivo `onion_init_fix.go` esté presente en tu proyecto.

### Problema: Error "undefined: onion"

Este error ocurre cuando el paquete `onion` no está importado correctamente. Para solucionarlo, asegúrate de que el paquete `onion` esté presente en tu proyecto y que las importaciones sean correctas.

### Problema: Error "cannot find package"

Este error ocurre cuando Go no puede encontrar un paquete. Para solucionarlo, asegúrate de que el paquete esté presente en tu proyecto o en tu GOPATH.

## Notas adicionales

- El archivo `onion_init_fix.go` proporciona una implementación mínima de la función `initRealOnionRouting` para que la compilación funcione. En una implementación real, esta función debería llamar a `onion.InitOnionRouting`.
- Si quieres implementar el enrutamiento cebolla real, consulta el archivo `ONION_ROUTING_INTEGRATION_FIXED.md` para obtener instrucciones detalladas.
