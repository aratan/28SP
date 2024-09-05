package main

import (
    "log"
    "net/http"
)

func main() {
    // Ruta para servir archivos estáticos
    fs := http.FileServer(http.Dir("./web"))
    
    // Registrar el servidor de archivos estáticos
    http.Handle("/", fs)
    
    // Iniciar el servidor en el puerto 80
    log.Println("Servidor web ejecutándose en http://localhost:80")
    
    if err := http.ListenAndServe(":80", nil); err != nil {
        log.Fatalf("Error al iniciar el servidor: %v", err)
    }
}
