#!/bin/bash

# Generate private key
openssl genrsa -out key.pem 2048

# Generate CSR
openssl req -new -key key.pem -out csr.pem -subj "/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem
