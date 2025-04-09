#!/bin/bash

# Crear una red Docker para los nodos
docker network create p2p-network

# Construir la imagen Docker
docker build -t p2p-app .

# Ejecutar 5 nodos
for i in {1..5}; do
  # Crear el directorio para los archivos del nodo
  mkdir -p node$i

  # Copiar el archivo de configuración
  cp config-node$i.yaml node$i/config.yaml

  # Ejecutar el nodo
  docker run -d \
    --name p2p-node$i \
    --network p2p-network \
    -p 808$i:8080 \
    -e NODE_ID=node$i \
    -e P2P_PORT=4001 \
    -v $(pwd)/node$i:/app/data \
    p2p-app
done

# Mostrar los logs de los nodos
echo "Nodos iniciados. Para ver los logs, ejecuta:"
echo "docker logs -f p2p-node1"
echo "docker logs -f p2p-node2"
echo "docker logs -f p2p-node3"
echo "docker logs -f p2p-node4"
echo "docker logs -f p2p-node5"

# Para detener los nodos, ejecuta:
# docker stop p2p-node1 p2p-node2 p2p-node3 p2p-node4 p2p-node5
# docker rm p2p-node1 p2p-node2 p2p-node3 p2p-node4 p2p-node5
# docker network rm p2p-network
