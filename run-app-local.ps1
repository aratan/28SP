# Script para ejecutar la aplicación localmente

Write-Host "Compilando la aplicación..." -ForegroundColor Cyan
go build -o p2p-app.exe main.go

Write-Host "`nEjecutando la aplicación..." -ForegroundColor Cyan
.\p2p-app.exe -listen="/ip4/0.0.0.0/tcp/4001"
