# Script para detener todos los nodos

Write-Host "Deteniendo todos los nodos..." -ForegroundColor Cyan
Get-Process -Name p2p-app -ErrorAction SilentlyContinue | Stop-Process

Write-Host "Todos los nodos detenidos" -ForegroundColor Green
