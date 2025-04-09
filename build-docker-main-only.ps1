# Script para construir la imagen Docker con solo el archivo principal

Write-Host "Construyendo imagen Docker p2p-app con solo el archivo principal..." -ForegroundColor Cyan
docker build -t p2p-app -f Dockerfile.main_only .

Write-Host "`nPara verificar que la imagen se ha construido correctamente, ejecuta:" -ForegroundColor Yellow
Write-Host "docker images" -ForegroundColor White
