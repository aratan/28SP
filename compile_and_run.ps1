# Script para compilar y ejecutar el código

Write-Host "Compilando el código..." -ForegroundColor Cyan

# Compilar el código
go build

# Verificar si la compilación fue exitosa
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error al compilar el código" -ForegroundColor Red
    exit
}

Write-Host "Código compilado exitosamente" -ForegroundColor Green

# Ejecutar la aplicación
Write-Host "Ejecutando la aplicación..." -ForegroundColor Cyan
.\api-p2p-front.exe
