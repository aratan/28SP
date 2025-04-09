# Enrutamiento Cebolla Real para Aplicación P2P

Este proyecto implementa un sistema de enrutamiento cebolla real para una aplicación de mensajería P2P, proporcionando un alto nivel de anonimato y privacidad.

## Características

- **Enrutamiento cebolla real**: Cada mensaje se cifra con múltiples capas, una para cada nodo en la ruta.
- **Distribución de claves**: Los nodos intercambian claves públicas a través de un topic de control dedicado.
- **Selección de rutas aleatorias**: Las rutas se seleccionan aleatoriamente para cada mensaje.
- **Procesamiento por capas**: Cada nodo solo puede descifrar su capa y no conoce la ruta completa.
- **Integración con el sistema existente**: Compatible con el sistema de mensajería P2P existente.

## Componentes

1. **Topic de Control**: Gestiona la distribución de claves y la información de la red.
2. **Sistema de Enrutamiento Cebolla**: Implementa el enrutamiento cebolla real con múltiples capas de cifrado.
3. **Integración con el Sistema Existente**: Integra el enrutamiento cebolla real con el sistema existente.

## Cómo funciona

1. **Distribución de claves**:
   - Cada nodo genera un par de claves RSA (pública/privada)
   - Los nodos anuncian su presencia y clave pública en el topic de control
   - Los nodos almacenan las claves públicas de otros nodos

2. **Envío de mensajes**:
   - Se selecciona una ruta aleatoria a través de varios nodos
   - El mensaje se cifra con múltiples capas, una para cada nodo en la ruta
   - Cada capa contiene información sobre el siguiente nodo en la ruta
   - El mensaje se envía al primer nodo de la ruta

3. **Procesamiento en cada nodo**:
   - El nodo recibe el mensaje y verifica si es el destinatario actual
   - Descifra su capa con su clave privada
   - Extrae la información sobre el siguiente nodo
   - Reenvía el mensaje al siguiente nodo

4. **Destino final**:
   - El último nodo descifra la capa final
   - Extrae el mensaje original
   - Procesa el mensaje como un mensaje normal

## Prueba con Docker

Para probar el sistema con múltiples nodos, se proporciona una configuración Docker:

```bash
# Construir y ejecutar los contenedores
docker-compose up -d

# Ver los logs de un nodo específico
docker logs p2p-node1

# Detener los contenedores
docker-compose down
```

La configuración Docker crea 5 nodos que se comunican entre sí a través de la red P2P.

## Seguridad

Este sistema proporciona un alto nivel de anonimato y privacidad:

- **Anonimato del remitente**: El remitente original no es conocido por los nodos intermedios ni por el destinatario.
- **Anonimato del destinatario**: El destinatario no es conocido por los nodos intermedios.
- **Confidencialidad del mensaje**: El contenido del mensaje solo es conocido por el remitente y el destinatario.
- **Resistencia a análisis de tráfico**: El uso de múltiples capas de cifrado y rutas aleatorias dificulta el análisis de tráfico.

## Limitaciones

- **Rendimiento**: El enrutamiento cebolla introduce una sobrecarga de procesamiento y latencia.
- **Complejidad**: El sistema es más complejo que un sistema de mensajería P2P tradicional.
- **Dependencia de nodos**: El sistema requiere un número suficiente de nodos para proporcionar anonimato efectivo.
