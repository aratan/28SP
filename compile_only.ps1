# Script para compilar el código sin ejecutarlo

Write-Host "Compilando el código..." -ForegroundColor Cyan

# Compilar el código
go build

# Verificar si la compilación fue exitosa
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error al compilar el código" -ForegroundColor Red
    exit
}

Write-Host "Código compilado exitosamente" -ForegroundColor Green
Write-Host "Para ejecutar la aplicación, usa: .\api-p2p-front.exe" -ForegroundColor Yellow
