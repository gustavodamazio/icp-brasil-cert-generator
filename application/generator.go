package application

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/icp-brasil-cert-generator/domain"
)

// CertificateGeneratorService implements the certificate generation use cases
type CertificateGeneratorService struct {
	repository domain.CertificateRepository
	caCache    *domain.Certificate // Cache for CA certificate
}

// NewCertificateGeneratorService creates a new certificate generator service
func NewCertificateGeneratorService(repository domain.CertificateRepository) *CertificateGeneratorService {
	return &CertificateGeneratorService{
		repository: repository,
	}
}

// GenerateMultiple generates multiple certificates from a configuration
func (s *CertificateGeneratorService) GenerateMultiple(config *Config) ([]*domain.Certificate, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Convert to domain configs
	domainConfigs, err := config.ToCertificateConfigs()
	if err != nil {
		return nil, fmt.Errorf("failed to convert configurations: %w", err)
	}

	// Generate CA certificate if not cached
	if s.caCache == nil {
		ca, err := s.GenerateCA()
		if err != nil {
			return nil, domain.NewGenerationErrorWithCause("failed to generate CA certificate", err)
		}
		s.caCache = ca
	}

	// Generate certificates
	certificates := make([]*domain.Certificate, len(domainConfigs))
	for i, domainConfig := range domainConfigs {
		cert, err := s.Generate(domainConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to generate certificate %d (%s): %w", i+1, config.Certificates[i].Name, err)
		}
		certificates[i] = cert
	}

	return certificates, nil
}

// SaveMultipleCertificates saves multiple certificates with individual output directories
func (s *CertificateGeneratorService) SaveMultipleCertificates(certificates []*domain.Certificate, config *Config) error {
	for i, cert := range certificates {
		certConfig := config.Certificates[i]
		outputDir := config.GetCertificateOutputPath(certConfig.Name)

		// Create certificate-specific output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory for %s: %w", certConfig.Name, err)
		}

		// Save certificate in specified formats
		if err := s.SaveCertificatesWithFormats(cert, outputDir, config.Security.PFXPassword, config.Output.Formats); err != nil {
			return fmt.Errorf("failed to save certificate %s: %w", certConfig.Name, err)
		}
	}

	return nil
}

// Generate generates a new ICP Brasil certificate based on the provided configuration
func (s *CertificateGeneratorService) Generate(config domain.CertificateConfig) (*domain.Certificate, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Generate CA certificate if not cached
	if s.caCache == nil {
		ca, err := s.GenerateCA()
		if err != nil {
			return nil, domain.NewGenerationErrorWithCause("failed to generate CA certificate", err)
		}
		s.caCache = ca
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to generate private key", err)
	}

	// Create certificate template
	template, err := s.createCertificateTemplate(config)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to create certificate template", err)
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		s.caCache.X509Cert,
		&privateKey.PublicKey,
		s.caCache.PrivateKey,
	)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to create certificate", err)
	}

	// Parse the generated certificate
	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to parse generated certificate", err)
	}

	// Create domain certificate
	cert := &domain.Certificate{
		Type:       config.Type,
		PersonType: config.PersonType,
		SubjectDN: domain.SubjectDN{
			CommonName:         domain.SanitizeName(config.Name),
			OrganizationalUnit: config.OrgUnit,
			Organization:       "ICP-Brasil",
			Country:            "BR",
			SerialNumber:       config.Document,
		},
		ValidityPeriod: domain.ValidityPeriod{
			NotBefore: config.ValidFrom,
			NotAfter:  config.ValidUntil,
		},
		Extensions: s.createExtensions(config),
		PrivateKey: privateKey,
		X509Cert:   x509Cert,
	}

	return cert, nil
}

// GenerateCA generates a Certificate Authority certificate
func (s *CertificateGeneratorService) GenerateCA() (*domain.Certificate, error) {
	// Generate CA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to generate CA private key", err)
	}

	// Create CA certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "ICP-Brasil Mock CA",
			OrganizationalUnit: []string{"Mock Certificate Authority"},
			Organization:       []string{"ICP-Brasil"},
			Country:            []string{"BR"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	// Generate subject key identifier
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to marshal public key", err)
	}
	hash := sha1.Sum(pubKeyBytes)
	template.SubjectKeyId = hash[:]

	// Self-sign the CA certificate
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to create CA certificate", err)
	}

	// Parse the generated certificate
	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to parse CA certificate", err)
	}

	// Create domain certificate
	cert := &domain.Certificate{
		Type:       "CA",
		PersonType: domain.PersonTypeLegalEntity,
		SubjectDN: domain.SubjectDN{
			CommonName:         "ICP-Brasil Mock CA",
			OrganizationalUnit: "Mock Certificate Authority",
			Organization:       "ICP-Brasil",
			Country:            "BR",
		},
		ValidityPeriod: domain.ValidityPeriod{
			NotBefore: template.NotBefore,
			NotAfter:  template.NotAfter,
		},
		PrivateKey: privateKey,
		X509Cert:   x509Cert,
	}

	return cert, nil
}

// createCertificateTemplate creates an X.509 certificate template based on the configuration
func (s *CertificateGeneratorService) createCertificateTemplate(config domain.CertificateConfig) (*x509.Certificate, error) {
	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000000))
	if err != nil {
		return nil, err
	}

	// Create subject
	subject := pkix.Name{
		CommonName:         domain.SanitizeName(config.Name),
		OrganizationalUnit: []string{config.OrgUnit},
		Organization:       []string{"ICP-Brasil"},
		Country:            []string{"BR"},
		SerialNumber:       config.Document,
	}

	// Create template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    config.ValidFrom,
		NotAfter:     config.ValidUntil,
		KeyUsage:     s.getX509KeyUsage(config),
		ExtKeyUsage:  s.getX509ExtKeyUsage(config),
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			s.parseOID(config.GetPolicyOID()),
		},
		BasicConstraintsValid: false,
		IsCA:                  false,
	}

	// Add DNS names if provided
	if len(config.DNSNames) > 0 {
		template.DNSNames = config.DNSNames
	}

	// Add email if provided
	if config.Email != "" {
		template.EmailAddresses = []string{config.Email}
	}

	// Generate subject key identifier
	// This will be set after the certificate is created
	return template, nil
}

// createExtensions creates the domain extensions based on the configuration
func (s *CertificateGeneratorService) createExtensions(config domain.CertificateConfig) domain.Extensions {
	keyUsage := config.GetKeyUsage()

	return domain.Extensions{
		KeyUsage: keyUsage,
		BasicConstraints: domain.BasicConstraints{
			IsCA:     false,
			Critical: false,
		},
		CertificatePolicies: []domain.CertificatePolicy{
			{
				OID:    config.GetPolicyOID(),
				CPSUri: "https://mock.icp-brasil.gov.br/dpc",
			},
		},
		CRLDistributionPoints: []string{
			"https://mock.icp-brasil.gov.br/crl",
		},
		SubjectAltName: domain.SubjectAltName{
			EmailAddresses: []string{config.Email},
			DNSNames:       config.DNSNames,
		},
	}
}

// getX509KeyUsage converts domain key usage to x509 key usage
func (s *CertificateGeneratorService) getX509KeyUsage(config domain.CertificateConfig) x509.KeyUsage {
	keyUsage := config.GetKeyUsage()
	var x509KeyUsage x509.KeyUsage

	if keyUsage.DigitalSignature {
		x509KeyUsage |= x509.KeyUsageDigitalSignature
	}
	if keyUsage.NonRepudiation {
		x509KeyUsage |= x509.KeyUsageContentCommitment
	}
	if keyUsage.KeyEncipherment {
		x509KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if keyUsage.KeyCertSign {
		x509KeyUsage |= x509.KeyUsageCertSign
	}
	if keyUsage.CRLSign {
		x509KeyUsage |= x509.KeyUsageCRLSign
	}

	return x509KeyUsage
}

// getX509ExtKeyUsage converts domain extended key usage to x509 extended key usage
func (s *CertificateGeneratorService) getX509ExtKeyUsage(config domain.CertificateConfig) []x509.ExtKeyUsage {
	switch config.Type {
	case domain.TypeA3, domain.TypeA4:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case domain.TypeSES, domain.TypeSEH:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	case domain.TypeAES, domain.TypeAEH:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
}

// parseOID parses a string OID into an ObjectIdentifier
func (s *CertificateGeneratorService) parseOID(oidStr string) asn1.ObjectIdentifier {
	// Parse the OID string (e.g., "2.16.76.1.2.3.1")
	parts := strings.Split(oidStr, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))

	for i, part := range parts {
		val, err := strconv.Atoi(part)
		if err != nil {
			// Fallback to default ICP Brasil OID
			return asn1.ObjectIdentifier{2, 16, 76, 1, 2, 3, 1}
		}
		oid[i] = val
	}

	return oid
}

// SaveCertificates saves the certificate in the specified formats
func (s *CertificateGeneratorService) SaveCertificates(cert *domain.Certificate, outputDir, password string) error {
	// Save PEM format (default)
	keyPath := filepath.Join(outputDir, "certificate.key")
	certPath := filepath.Join(outputDir, "certificate.crt")
	if err := s.repository.SavePEM(cert, keyPath, certPath); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to save PEM certificate", err)
	}

	// Save PFX format (default)
	pfxPath := filepath.Join(outputDir, "certificate.pfx")
	if err := s.repository.SavePFX(cert, pfxPath, password); err != nil {
		return domain.NewPersistenceErrorWithCause("failed to save PFX certificate", err)
	}

	return nil
}

// SaveCertificatesWithFormats saves the certificate in the specified formats
func (s *CertificateGeneratorService) SaveCertificatesWithFormats(cert *domain.Certificate, outputDir, password string, formats []string) error {
	var savedFiles []string

	for _, format := range formats {
		switch strings.ToLower(format) {
		case "pem":
			keyPath := filepath.Join(outputDir, "certificate.key")
			certPath := filepath.Join(outputDir, "certificate.crt")
			if err := s.repository.SavePEM(cert, keyPath, certPath); err != nil {
				return domain.NewPersistenceErrorWithCause("failed to save PEM certificate", err)
			}
			savedFiles = append(savedFiles, "certificate.crt (PEM certificate)", "certificate.key (PEM private key)")

		case "pfx":
			pfxPath := filepath.Join(outputDir, "certificate.pfx")
			if err := s.repository.SavePFX(cert, pfxPath, password); err != nil {
				return domain.NewPersistenceErrorWithCause("failed to save PFX certificate", err)
			}
			savedFiles = append(savedFiles, "certificate.pfx (PKCS#12)")

		case "cert":
			certPath := filepath.Join(outputDir, "certificate.cert")
			if err := s.repository.SaveCERT(cert, certPath); err != nil {
				return domain.NewPersistenceErrorWithCause("failed to save CERT certificate", err)
			}
			savedFiles = append(savedFiles, "certificate.cert (DER certificate)")

		case "crt":
			crtPath := filepath.Join(outputDir, "certificate.crt")
			if err := s.repository.SaveCRT(cert, crtPath); err != nil {
				return domain.NewPersistenceErrorWithCause("failed to save CRT certificate", err)
			}
			savedFiles = append(savedFiles, "certificate.crt (DER certificate)")

		default:
			return fmt.Errorf("unsupported format: %s", format)
		}
	}

	return nil
}
