#!/bin/bash

# Detener los nodos
docker stop p2p-node1 p2p-node2 p2p-node3 p2p-node4 p2p-node5

# Eliminar los contenedores
docker rm p2p-node1 p2p-node2 p2p-node3 p2p-node4 p2p-node5

# Eliminar la red
docker network rm p2p-network

# Eliminar los directorios de los nodos
rm -rf node1 node2 node3 node4 node5

echo "Limpieza completada"
