# Script para compilar y ejecutar el código con enrutamiento cebolla real

Write-Host "Compilando el código con enrutamiento cebolla real..." -ForegroundColor Cyan

# Compilar el código
go build -o p2p-app.exe

# Verificar si la compilación fue exitosa
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error al compilar el código" -ForegroundColor Red
    exit
}

Write-Host "Código compilado exitosamente" -ForegroundColor Green

# Ejecutar la aplicación
Write-Host "Ejecutando la aplicación con enrutamiento cebolla real..." -ForegroundColor Cyan
.\p2p-app.exe -listen="/ip4/0.0.0.0/tcp/4001"
