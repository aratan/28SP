FROM golang:1.22-alpine

WORKDIR /app

# Instalar dependencias del sistema
RUN apk add --no-cache git gcc musl-dev

# Copiar archivos de código fuente
COPY . .

# Descargar dependencias
RUN go mod download

# Compilar la aplicación
RUN go build -o p2p-app .

# Exponer puertos
EXPOSE 8080
EXPOSE 4001

# Comando para ejecutar la aplicación
CMD ["/app/p2p-app"]
