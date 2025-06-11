package infrastructure

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/yourorg/icp-brasil-cert-generator/domain"
)

// FileRepository implements certificate persistence to the file system
type FileRepository struct{}

// NewFileRepository creates a new file repository
func NewFileRepository() *FileRepository {
	return &FileRepository{}
}

// SavePEM saves the certificate and private key in PEM format
func (r *FileRepository) SavePEM(cert *domain.Certificate, keyPath, certPath string) error {
	// Ensure directories exist
	if err := r.ensureDir(filepath.Dir(keyPath)); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to create key directory", err)
	}
	if err := r.ensureDir(filepath.Dir(certPath)); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to create certificate directory", err)
	}

	// Save private key
	if err := r.savePrivateKeyPEM(cert, keyPath); err != nil {
		return err
	}

	// Save certificate
	if err := r.saveCertificatePEM(cert, certPath); err != nil {
		return err
	}

	return nil
}

// SavePFX saves the certificate and private key in PFX/PKCS#12 format
func (r *FileRepository) SavePFX(cert *domain.Certificate, path, password string) error {
	// Ensure directory exists
	if err := r.ensureDir(filepath.Dir(path)); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to create PFX directory", err)
	}

	// Encode to PFX using the modern encoder for security
	pfxData, err := pkcs12.Modern2023.Encode(
		cert.PrivateKey,
		cert.X509Cert,
		nil, // CA certificates (nil for end-entity certificates)
		password,
	)
	if err != nil {
		return domain.NewPersistenceErrorWithCause("failed to encode PFX", err)
	}

	// Write PFX file
	if err := os.WriteFile(path, pfxData, 0600); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to write PFX file", err)
	}

	return nil
}

// SaveCERT saves the certificate in DER format with .cert extension
func (r *FileRepository) SaveCERT(cert *domain.Certificate, path string) error {
	// Ensure directory exists
	if err := r.ensureDir(filepath.Dir(path)); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to create CERT directory", err)
	}

	// Write certificate in DER format (X.509 DER encoding)
	if err := os.WriteFile(path, cert.X509Cert.Raw, 0644); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to write CERT file", err)
	}

	return nil
}

// SaveCRT saves the certificate in DER format with .crt extension
func (r *FileRepository) SaveCRT(cert *domain.Certificate, path string) error {
	// Ensure directory exists
	if err := r.ensureDir(filepath.Dir(path)); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to create CRT directory", err)
	}

	// Write certificate in DER format (X.509 DER encoding)
	if err := os.WriteFile(path, cert.X509Cert.Raw, 0644); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to write CRT file", err)
	}

	return nil
}

// savePrivateKeyPEM saves the private key in PEM format
func (r *FileRepository) savePrivateKeyPEM(cert *domain.Certificate, keyPath string) error {
	// Marshal private key to PKCS#8 format
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return domain.NewPersistenceErrorWithCause("failed to marshal private key", err)
	}

	// Create PEM block
	keyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Create key file
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return domain.NewPersistenceErrorWithCause("failed to create private key file", err)
	}
	defer keyFile.Close()

	// Write PEM encoded key
	if err := pem.Encode(keyFile, keyPEM); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to write private key PEM", err)
	}

	return nil
}

// saveCertificatePEM saves the certificate in PEM format
func (r *FileRepository) saveCertificatePEM(cert *domain.Certificate, certPath string) error {
	// Create PEM block
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.X509Cert.Raw,
	}

	// Create certificate file
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return domain.NewPersistenceErrorWithCause("failed to create certificate file", err)
	}
	defer certFile.Close()

	// Write PEM encoded certificate
	if err := pem.Encode(certFile, certPEM); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to write certificate PEM", err)
	}

	return nil
}

// ensureDir ensures that a directory exists, creating it if necessary
func (r *FileRepository) ensureDir(dir string) error {
	if dir == "" {
		return nil
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

// SaveCertificateChain saves a certificate chain in PEM format
func (r *FileRepository) SaveCertificateChain(certs []*domain.Certificate, chainPath string) error {
	// Ensure directory exists
	if err := r.ensureDir(filepath.Dir(chainPath)); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to create chain directory", err)
	}

	// Create chain file
	chainFile, err := os.OpenFile(chainPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return domain.NewPersistenceErrorWithCause("failed to create chain file", err)
	}
	defer chainFile.Close()

	// Write each certificate in the chain
	for _, cert := range certs {
		certPEM := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.X509Cert.Raw,
		}

		if err := pem.Encode(chainFile, certPEM); err != nil {
			return domain.NewPersistenceErrorWithCause("failed to write certificate to chain", err)
		}
	}

	return nil
}

// LoadCertificatePEM loads a certificate from a PEM file
func (r *FileRepository) LoadCertificatePEM(certPath string) (*x509.Certificate, error) {
	// Read certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, domain.NewPersistenceErrorWithCause("failed to read certificate file", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, domain.NewPersistenceError("failed to decode PEM block")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, domain.NewPersistenceErrorWithCause("failed to parse certificate", err)
	}

	return cert, nil
}

// LoadCertificateDER loads a certificate from a DER file (.cert or .crt)
func (r *FileRepository) LoadCertificateDER(certPath string) (*x509.Certificate, error) {
	// Read certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, domain.NewPersistenceErrorWithCause("failed to read certificate file", err)
	}

	// Parse certificate directly from DER bytes
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, domain.NewPersistenceErrorWithCause("failed to parse DER certificate", err)
	}

	return cert, nil
}

// LoadPFX loads a certificate and private key from a PFX file
func (r *FileRepository) LoadPFX(pfxPath, password string) (*domain.Certificate, error) {
	// Read PFX file
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, domain.NewPersistenceErrorWithCause("failed to read PFX file", err)
	}

	// Decode PFX
	privateKey, cert, caCerts, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, domain.NewPersistenceErrorWithCause("failed to decode PFX", err)
	}

	// Convert private key to RSA (assuming RSA keys)
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, domain.NewPersistenceError("private key is not RSA")
	}

	// Create domain certificate
	domainCert := &domain.Certificate{
		PrivateKey: rsaKey,
		X509Cert:   cert,
		// Note: Other fields would need to be extracted from the certificate
	}

	// Store CA certificates if needed
	_ = caCerts // For future use

	return domainCert, nil
}
