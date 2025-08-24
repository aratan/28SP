// +build ignore

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// Generar clave privada
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error al generar clave privada: %v", err)
	}

	// Crear plantilla para el certificado
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Válido por 1 año

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Error al generar número de serie: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Desarrollo Local"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Crear certificado autofirmado
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Error al crear certificado: %v", err)
	}

	// Guardar certificado en cert.pem
	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("Error al crear cert.pem: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Error al codificar certificado: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error al cerrar cert.pem: %v", err)
	}
	log.Println("Certificado escrito en cert.pem")

	// Guardar clave privada en key.pem
	keyOut, err := os.Create("key.pem")
	if err != nil {
		log.Fatalf("Error al crear key.pem: %v", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Error al codificar clave privada: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error al cerrar key.pem: %v", err)
	}
	log.Println("Clave privada escrita en key.pem")

	// Crear CSR (Certificate Signing Request)
	template.SignatureAlgorithm = x509.SHA256WithRSA
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            template.Subject,
		SignatureAlgorithm: template.SignatureAlgorithm,
		DNSNames:           template.DNSNames,
		IPAddresses:        template.IPAddresses,
	}, privateKey)
	if err != nil {
		log.Fatalf("Error al crear CSR: %v", err)
	}

	// Guardar CSR en csr.pem
	csrOut, err := os.Create("csr.pem")
	if err != nil {
		log.Fatalf("Error al crear csr.pem: %v", err)
	}
	if err := pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		log.Fatalf("Error al codificar CSR: %v", err)
	}
	if err := csrOut.Close(); err != nil {
		log.Fatalf("Error al cerrar csr.pem: %v", err)
	}
	log.Println("CSR escrito en csr.pem")
}
