# Script para ejecutar el código con argumentos específicos

param(
    [string]$listen = "/ip4/0.0.0.0/tcp/4001",
    [string]$port = "8080",
    [string]$nodeId = "node1"
)

Write-Host "Ejecutando la aplicación con los siguientes argumentos:" -ForegroundColor Cyan
Write-Host "  listen: $listen" -ForegroundColor Cyan
Write-Host "  port: $port" -ForegroundColor Cyan
Write-Host "  nodeId: $nodeId" -ForegroundColor Cyan

# Ejecutar la aplicación
.\p2p-app.exe -listen="$listen" -port="$port" -node-id="$nodeId"
