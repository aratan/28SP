# Script para integrar el enrutamiento cebolla en el código principal

Write-Host "Integrando el enrutamiento cebolla en el código principal..." -ForegroundColor Cyan

# Crear un archivo temporal con las modificaciones
$tempFile = "main_with_onion.go"

# Leer el contenido del archivo main.go
$mainContent = Get-Content -Path "main.go" -Raw

# Buscar la función main
$mainFunctionPattern = "func main\(\) \{"
$mainFunctionIndex = $mainContent.IndexOf($mainFunctionPattern)

if ($mainFunctionIndex -eq -1) {
    Write-Host "No se encontró la función main en el archivo main.go" -ForegroundColor Red
    exit
}

# Encontrar el final de la inicialización en la función main
$initEndPattern = "log.Println(\"P2P node started successfully\")"
$initEndIndex = $mainContent.IndexOf($initEndPattern, $mainFunctionIndex)

if ($initEndIndex -eq -1) {
    Write-Host "No se encontró el final de la inicialización en la función main" -ForegroundColor Red
    exit
}

# Insertar la inicialización del enrutamiento cebolla
$onionInitCode = @"

	// Inicializar el enrutamiento cebolla
	if err := initOnionRouting(ctx); err != nil {
		log.Printf("Failed to initialize onion routing: %v", err)
	} else {
		log.Println("Onion routing initialized successfully")
	}
"@

# Insertar el código después del final de la inicialización
$newMainContent = $mainContent.Insert($initEndIndex + $initEndPattern.Length, $onionInitCode)

# Guardar el archivo temporal
Set-Content -Path $tempFile -Value $newMainContent

Write-Host "`nArchivo temporal creado: $tempFile" -ForegroundColor Green
Write-Host "Para compilar y ejecutar la aplicación con enrutamiento cebolla, ejecuta:" -ForegroundColor Yellow
Write-Host "go build -o p2p-app.exe $tempFile onion_integration.go" -ForegroundColor White
Write-Host ".\p2p-app.exe -config config\config.yaml" -ForegroundColor White
