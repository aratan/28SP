# Script para ejecutar la aplicación con un archivo de configuración personalizado

# Crear un directorio para la configuración
if (-not (Test-Path -Path "config")) {
    New-Item -ItemType Directory -Path "config" | Out-Null
}

# Crear un archivo de configuración YAML personalizado
$configContent = @"
# Configuración básica
topicName: "p2p-network"
encryptionKey: "node1-encryption-key-12345678901234567890123456789012"
logLevel: "debug"
maxMessageSize: 10

# Direcciones de escucha
listenAddresses:
  - /ip4/0.0.0.0/tcp/4001
webListenAddress: 0.0.0.0:8080

# Configuración de mDNS
mdns:
  enabled: true
  serviceTag: "p2p-app"

# Usuarios
users:
  - username: "Node1"
    password: "password1"
    photo: "https://example.com/avatar1.png"

# Configuración de seguridad
security:
  endToEndEncryption: true
  encryptionKey: "node1-encryption-key-12345678901234567890123456789012"
  keyRotation: true
  keyRotationInterval: 3600
  onionRouting: true
  minHops: 2
  maxHops: 4
  anonymousMessages: true
  anonymitySetSize: 5
  trafficMixing: true
  trafficMixingInterval: 60
  dummyMessages: true
  dummyMessageInterval: 300
  messageTTL: 3600
"@
Set-Content -Path "config\config.yaml" -Value $configContent

Write-Host "Compilando la aplicación..." -ForegroundColor Cyan
go build -o p2p-app.exe main.go

Write-Host "`nEjecutando la aplicación con configuración personalizada..." -ForegroundColor Cyan
.\p2p-app.exe -config config\config.yaml
