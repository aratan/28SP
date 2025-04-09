# Crear un archivo de configuración YAML completo
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

# ... (más configuración)
"@
Set-Content -Path "config\config-complete.yaml" -Value $configContent

docker run -d `
    --name p2p-app `
    -p "8080:8080" `
    -p "4001:4001" `
    -v "${PWD}\config:/app/config" `
    -e "NODE_ID=node1" `
    p2p-app /app/p2p-app -config /app/config/config-complete.yaml