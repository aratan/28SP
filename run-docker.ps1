# Crear un archivo de configuración personalizado
$configContent = @"
{
  "ListenAddresses": ["/ip4/0.0.0.0/tcp/4001"],
  "WebListenAddress": "0.0.0.0:8080",
  "NodeID": "node1"
}
"@
Set-Content -Path "config\config.json" -Value $configContent

docker run -d `
    --name p2p-app `
    -p "8080:8080" `
    -p "4001:4001" `
    -v "${PWD}\config:/app/config" `
    -e "NODE_ID=node1" `
    p2p-app /app/p2p-app -config /app/config/config.json