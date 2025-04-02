# Create configuration file for OpenSSL
@"
[req]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
C = ES
ST = Madrid
L = Madrid
O = Development
OU = Development
CN = localhost

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
"@ | Out-File -FilePath ".\openssl.cnf" -Encoding ascii

# Generate private key
openssl genrsa -out key.pem 2048

# Generate CSR using the configuration file
openssl req -new -key key.pem -out csr.pem -config openssl.cnf

# Generate self-signed certificate
openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem -extensions v3_req -extfile openssl.cnf

# Clean up configuration file
Remove-Item ".\openssl.cnf"
