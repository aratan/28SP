# aplicación de mensajería distribuida (DMA)

![12f4413a-c382-4448-bedb-e4e82c5c43a8](https://github.com/user-attachments/assets/3c0e7822-71a7-4559-ab21-0a56c89f051c)

## utilizando la biblioteca libp2p de Go. Aquí está un resumen de sus características principales:

1. Cifrado:

1. Utiliza cifrado AES-GCM para encriptar los mensajes.
2. Implementa un sistema de cifrado de capas múltiples (mixnet) para mayor seguridad.



2. Protocolos:

1. Utiliza el protocolo libp2p para la comunicación peer-to-peer.
2. Implementa un sistema de publicación-suscripción (pubsub) para la distribución de mensajes.
3. Utiliza mDNS para el descubrimiento de pares en la red local.
4. Implementa una tabla de hash distribuida (DHT) para el descubrimiento de pares en redes más amplias.



3. Privacidad y Seguridad:

1. Los mensajes están cifrados de extremo a extremo.
2. Utiliza un sistema de capas múltiples de cifrado que puede proporcionar cierto grado de anonimato.
3. Implementa autenticación mediante tokens JWT para algunas rutas de la API.



4. Resistencia a la censura:

1. Al ser una red P2P, es inherentemente resistente a la censura centralizada.
2. El uso de DHT permite el descubrimiento de pares incluso si algunos nodos son bloqueados.



5. Características adicionales:

1. Compresión de mensajes usando gzip.
2. Sistema de "tablones" para organizar mensajes.
3. Funcionalidad para dar "me gusta" a mensajes y tablones.
4. Logging de eventos del sistema.





Para mejorar el código, se podrían considerar las siguientes modificaciones:

1. Añadir video
2. Implementar un mejor manejo de errores y recuperación en caso de fallos de red.
3. Mejorar la gestión de claves, posiblemente implementando un sistema de intercambio de claves.
4. Agregar más capas de anonimato, como el enrutamiento de cebolla.
5. Implementar un sistema de reputación para los pares para mejorar la confiabilidad de la red.

   ![image](https://github.com/user-attachments/assets/efd225bd-88ee-4e5a-b963-239e867b2bb8)

Cifrado de mensajes:

- La función `encryptMessage` utiliza AES-GCM para cifrar los mensajes.
- La función `mixnetEncrypt` aplica múltiples capas de cifrado utilizando diferentes claves.



Descifrado de mensajes:

- La función `decryptMessage` descifra los mensajes cifrados con AES-GCM.
- La función `mixnetDecrypt` aplica múltiples capas de descifrado en orden inverso.



Serialización y deserialización segura:

- `serializeMessage` comprime, cifra y serializa los mensajes antes de enviarlos.
- `deserializeMessage` deserializa, descifra y descomprime los mensajes recibidos.



Uso de libp2p para comunicación P2P:

- Implementa una red P2P utilizando libp2p, lo que dificulta el rastreo de los mensajes.



Enrutamiento de mensajes:

- La función `routeMessage` añade un retraso aleatorio, lo que puede ayudar a prevenir ataques de análisis de tráfico.



Anonimato de usuarios:

- Los mensajes utilizan una estructura `UserInfo` que no requiere información personal identificable.



Compresión de datos:

- Las funciones `compress` y `decompress` añaden una capa adicional de ofuscación a los datos.



Autenticación con JWT:

- Implementa autenticación basada en tokens JWT, lo que permite el acceso seguro sin exponer credenciales.


En general, este código proporciona una base sólida para una aplicación de mensajería distribuida y resistente a la censura, con un buen nivel de privacidad y seguridad.




## trabajando en la automatizacion de noticias con IA



Compilar desde termux en android

go build -ldflags="-checklinkname=0" -o myapp main.go


choco install openssl.light
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem

genera: csr.pem y  key.pem


# Generate private key
openssl genrsa -out key.pem 2048

# Generate CSR
openssl req -new -key key.pem -out csr.pem -subj "/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem


generara:          cert.pem

tcp.port == 8443 && ip.addr == 127.0.0.1
