@echo off
echo Generando certificados SSL para el servidor web...

REM Crear un archivo de configuración para OpenSSL
echo [req] > openssl.cnf
echo default_bits = 2048 >> openssl.cnf
echo prompt = no >> openssl.cnf
echo default_md = sha256 >> openssl.cnf
echo x509_extensions = v3_req >> openssl.cnf
echo distinguished_name = dn >> openssl.cnf
echo. >> openssl.cnf
echo [dn] >> openssl.cnf
echo C = ES >> openssl.cnf
echo ST = Madrid >> openssl.cnf
echo L = Madrid >> openssl.cnf
echo O = Development >> openssl.cnf
echo OU = Development >> openssl.cnf
echo CN = localhost >> openssl.cnf
echo. >> openssl.cnf
echo [v3_req] >> openssl.cnf
echo subjectAltName = @alt_names >> openssl.cnf
echo basicConstraints = CA:FALSE >> openssl.cnf
echo keyUsage = digitalSignature, nonRepudiation, keyEncipherment >> openssl.cnf
echo. >> openssl.cnf
echo [alt_names] >> openssl.cnf
echo DNS.1 = localhost >> openssl.cnf
echo IP.1 = 127.0.0.1 >> openssl.cnf

REM Generar clave privada
openssl genrsa -out key.pem 2048

REM Generar CSR usando el archivo de configuración
openssl req -new -key key.pem -out csr.pem -config openssl.cnf

REM Generar certificado autofirmado
openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem -extensions v3_req -extfile openssl.cnf

REM Limpiar el archivo de configuración
del openssl.cnf

echo Certificados generados correctamente:
echo - key.pem (clave privada)
echo - cert.pem (certificado)
echo - csr.pem (solicitud de firma de certificado)
