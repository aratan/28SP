# Script para ejecutar múltiples nodos

# Compilar el código
Write-Host "Compilando el código..." -ForegroundColor Cyan
go build -o p2p-app.exe

# Verificar si la compilación fue exitosa
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error al compilar el código" -ForegroundColor Red
    exit
}

Write-Host "Código compilado exitosamente" -ForegroundColor Green

# Crear directorios para los nodos
for ($i = 1; $i -le 5; $i++) {
    if (-not (Test-Path -Path "node$i")) {
        New-Item -ItemType Directory -Path "node$i" | Out-Null
    }
    
    # Copiar el ejecutable a cada directorio
    Copy-Item -Path "p2p-app.exe" -Destination "node$i\p2p-app.exe" -Force
}

# Ejecutar múltiples nodos
for ($i = 1; $i -le 5; $i++) {
    $port = 8080 + $i
    $p2pPort = 4000 + $i
    
    Write-Host "Ejecutando nodo $i en puerto $port (P2P: $p2pPort)..." -ForegroundColor Cyan
    
    Start-Process -FilePath "node$i\p2p-app.exe" -ArgumentList "-listen=/ip4/0.0.0.0/tcp/$p2pPort -port=$port -node-id=node$i" -WorkingDirectory "node$i" -NoNewWindow
}

Write-Host "`nNodos iniciados. Para acceder a las interfaces web:" -ForegroundColor Yellow
for ($i = 1; $i -le 5; $i++) {
    $port = 8080 + $i
    Write-Host "Nodo $i: http://localhost:$port" -ForegroundColor White
}

Write-Host "`nPara detener los nodos, cierra las ventanas de los procesos o ejecuta:" -ForegroundColor Yellow
Write-Host "Get-Process -Name p2p-app | Stop-Process" -ForegroundColor White
