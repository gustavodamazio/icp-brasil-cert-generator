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

// ICPBrasilCAChain represents the complete ICP-Brasil certificate chain
type ICPBrasilCAChain struct {
	RootCA         *domain.Certificate // Autoridade Certificadora Raiz Brasileira v5
	IntermediateCA *domain.Certificate // AC Mock (similar to AC SyngularID)
	IssuingCA      *domain.Certificate // AC Mock Multipla (similar to AC SyngularID Multipla)
}

// CertificateGeneratorService implements the certificate generation use cases
type CertificateGeneratorService struct {
	repository domain.CertificateRepository
	caChain    *ICPBrasilCAChain // Complete CA chain cache
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

	// Generate complete CA chain if not cached
	if s.caChain == nil {
		chain, err := s.GenerateCAChain()
		if err != nil {
			return nil, domain.NewGenerationErrorWithCause("failed to generate CA chain", err)
		}
		s.caChain = chain
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

	// Generate complete CA chain if not cached
	if s.caChain == nil {
		chain, err := s.GenerateCAChain()
		if err != nil {
			return nil, domain.NewGenerationErrorWithCause("failed to generate CA chain", err)
		}
		s.caChain = chain
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to generate private key", err)
	}

	// Generate subject key identifier
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to marshal public key", err)
	}
	subjectKeyID := sha1.Sum(pubKeyBytes)

	// Create certificate template with production-like structure
	template, err := s.createCertificateTemplate(config, subjectKeyID[:])
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to create certificate template", err)
	}

	// Sign certificate with the Issuing CA (AC Mock Multipla)
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		s.caChain.IssuingCA.X509Cert,
		&privateKey.PublicKey,
		s.caChain.IssuingCA.PrivateKey,
	)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to create certificate", err)
	}

	// Parse the generated certificate
	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to parse generated certificate", err)
	}

	// Build the CA chain for the end-entity certificate
	caChain := []*x509.Certificate{
		s.caChain.IssuingCA.X509Cert,
		s.caChain.IntermediateCA.X509Cert,
		s.caChain.RootCA.X509Cert,
	}

	// Create domain certificate with chain
	cert := &domain.Certificate{
		Type:       config.Type,
		PersonType: config.PersonType,
		SubjectDN: domain.SubjectDN{
			CommonName:         s.formatCommonName(config),
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
		CAChain:    caChain,
	}

	return cert, nil
}

// formatCommonName formats the Common Name according to ICP-Brasil standards
// For individuals: "NAME:CPF", for legal entities: "NAME:CNPJ"
func (s *CertificateGeneratorService) formatCommonName(config domain.CertificateConfig) string {
	sanitizedName := domain.SanitizeName(config.Name)
	return fmt.Sprintf("%s:%s", sanitizedName, config.Document)
}

// GenerateCAChain generates the complete ICP-Brasil certificate chain
// This mimics the real chain: Root CA → Intermediate CA → Issuing CA
func (s *CertificateGeneratorService) GenerateCAChain() (*ICPBrasilCAChain, error) {
	// 1. Generate Root CA (Autoridade Certificadora Raiz Brasileira v5)
	rootCA, err := s.generateRootCA()
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to generate Root CA", err)
	}

	// 2. Generate Intermediate CA (AC Mock - similar to AC SyngularID)
	intermediateCA, err := s.generateIntermediateCA(rootCA)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to generate Intermediate CA", err)
	}

	// 3. Generate Issuing CA (AC Mock Multipla - similar to AC SyngularID Multipla)
	issuingCA, err := s.generateIssuingCA(intermediateCA)
	if err != nil {
		return nil, domain.NewGenerationErrorWithCause("failed to generate Issuing CA", err)
	}

	return &ICPBrasilCAChain{
		RootCA:         rootCA,
		IntermediateCA: intermediateCA,
		IssuingCA:      issuingCA,
	}, nil
}

// generateRootCA generates the Root CA certificate (Autoridade Certificadora Raiz Brasileira v5)
func (s *CertificateGeneratorService) generateRootCA() (*domain.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// Generate subject key identifier
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	subjectKeyID := sha1.Sum(pubKeyBytes)

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000000000))

	// Build Certificate Policies extension for Root CA
	certPoliciesExt, err := s.buildCertificatePoliciesExtension([]asn1.ObjectIdentifier{
		{2, 16, 76, 1, 1, 0}, // Root policy OID
	})
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "Autoridade Certificadora Raiz Brasileira v5",
			OrganizationalUnit: []string{"Instituto Nacional de Tecnologia da Informacao - ITI"},
			Organization:       []string{"ICP-Brasil"},
			Country:            []string{"BR"},
		},
		NotBefore:             time.Now().AddDate(-8, 0, 0), // Started ~8 years ago (like real one from 2016)
		NotAfter:              time.Now().AddDate(5, 0, 0),  // Valid for ~5 more years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1, // No limit
		MaxPathLenZero:        false,
		SubjectKeyId:          subjectKeyID[:],
		AuthorityKeyId:        subjectKeyID[:], // Self-signed, so same as subject
		CRLDistributionPoints: []string{"http://acraiz.icpbrasil.gov.br/LCRacraizv5.crl"},
		ExtraExtensions:       []pkix.Extension{certPoliciesExt},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &domain.Certificate{
		Type:       "CA",
		PersonType: domain.PersonTypeLegalEntity,
		SubjectDN: domain.SubjectDN{
			CommonName:         "Autoridade Certificadora Raiz Brasileira v5",
			OrganizationalUnit: "Instituto Nacional de Tecnologia da Informacao - ITI",
			Organization:       "ICP-Brasil",
			Country:            "BR",
		},
		ValidityPeriod: domain.ValidityPeriod{
			NotBefore: template.NotBefore,
			NotAfter:  template.NotAfter,
		},
		PrivateKey: privateKey,
		X509Cert:   x509Cert,
	}, nil
}

// generateIntermediateCA generates the Intermediate CA (AC Mock - similar to AC SyngularID)
func (s *CertificateGeneratorService) generateIntermediateCA(rootCA *domain.Certificate) (*domain.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// Generate subject key identifier
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	subjectKeyID := sha1.Sum(pubKeyBytes)

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000000000))

	// Build Certificate Policies extension for Intermediate CA
	certPoliciesExt, err := s.buildCertificatePoliciesExtension([]asn1.ObjectIdentifier{
		{2, 16, 76, 1, 1, 156}, // Intermediate policy OID
	})
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "AC Mock",
			OrganizationalUnit: []string{"Autoridade Certificadora Raiz Brasileira v5"},
			Organization:       []string{"ICP-Brasil"},
			Country:            []string{"BR"},
		},
		NotBefore:             time.Now().AddDate(-3, 0, 0), // Started ~3 years ago
		NotAfter:              time.Now().AddDate(4, 0, 0),  // Valid for ~4 more years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		MaxPathLenZero:        false,
		SubjectKeyId:          subjectKeyID[:],
		AuthorityKeyId:        rootCA.X509Cert.SubjectKeyId,
		CRLDistributionPoints: []string{"http://acraiz.icpbrasil.gov.br/LCRacraizv5.crl"},
		ExtraExtensions:       []pkix.Extension{certPoliciesExt},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCA.X509Cert, &privateKey.PublicKey, rootCA.PrivateKey)
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &domain.Certificate{
		Type:       "CA",
		PersonType: domain.PersonTypeLegalEntity,
		SubjectDN: domain.SubjectDN{
			CommonName:         "AC Mock",
			OrganizationalUnit: "Autoridade Certificadora Raiz Brasileira v5",
			Organization:       "ICP-Brasil",
			Country:            "BR",
		},
		ValidityPeriod: domain.ValidityPeriod{
			NotBefore: template.NotBefore,
			NotAfter:  template.NotAfter,
		},
		PrivateKey: privateKey,
		X509Cert:   x509Cert,
	}, nil
}

// generateIssuingCA generates the Issuing CA (AC Mock Multipla - similar to AC SyngularID Multipla)
func (s *CertificateGeneratorService) generateIssuingCA(intermediateCA *domain.Certificate) (*domain.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// Generate subject key identifier
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	subjectKeyID := sha1.Sum(pubKeyBytes)

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000000000))

	// Build Certificate Policies extension for Issuing CA (2 policies like production)
	certPoliciesExt, err := s.buildCertificatePoliciesExtension([]asn1.ObjectIdentifier{
		{2, 16, 76, 1, 2, 1, 133}, // End-entity policy OID (like production)
		{2, 16, 76, 1, 2, 3, 125}, // Additional policy OID
	})
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "AC Mock Multipla",
			OrganizationalUnit: []string{"AC Mock"},
			Organization:       []string{"ICP-Brasil"},
			Country:            []string{"BR"},
		},
		NotBefore:             time.Now().AddDate(-2, 0, 0), // Started ~2 years ago
		NotAfter:              time.Now().AddDate(5, 0, 0),  // Valid for ~5 more years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		MaxPathLenZero:        false,
		SubjectKeyId:          subjectKeyID[:],
		AuthorityKeyId:        intermediateCA.X509Cert.SubjectKeyId,
		CRLDistributionPoints: []string{
			"http://mock.icp-brasil.gov.br/repositorio/ac-mock/lcr/lcr-ac-mock.crl",
			"http://icp-brasil.mock.gov.br/repositorio/ac-mock/lcr/lcr-ac-mock.crl",
		},
		ExtraExtensions: []pkix.Extension{certPoliciesExt},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, intermediateCA.X509Cert, &privateKey.PublicKey, intermediateCA.PrivateKey)
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &domain.Certificate{
		Type:       "CA",
		PersonType: domain.PersonTypeLegalEntity,
		SubjectDN: domain.SubjectDN{
			CommonName:         "AC Mock Multipla",
			OrganizationalUnit: "AC Mock",
			Organization:       "ICP-Brasil",
			Country:            "BR",
		},
		ValidityPeriod: domain.ValidityPeriod{
			NotBefore: template.NotBefore,
			NotAfter:  template.NotAfter,
		},
		PrivateKey: privateKey,
		X509Cert:   x509Cert,
	}, nil
}

// GenerateCA generates a Certificate Authority certificate (legacy method for compatibility)
func (s *CertificateGeneratorService) GenerateCA() (*domain.Certificate, error) {
	chain, err := s.GenerateCAChain()
	if err != nil {
		return nil, err
	}
	s.caChain = chain
	return chain.IssuingCA, nil
}

// createCertificateTemplate creates an X.509 certificate template based on the configuration
// This template closely mimics ICP-Brasil production certificates
func (s *CertificateGeneratorService) createCertificateTemplate(config domain.CertificateConfig, subjectKeyID []byte) (*x509.Certificate, error) {
	// Generate serial number (10 bytes like production)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(80), nil))
	if err != nil {
		return nil, err
	}

	// Create organizational units like production certificates
	// Production format: ["Certificado Digital PF A1", "Videoconferencia", "CNPJ_CA", "AC SyngularID Multipla"]
	orgUnits := s.buildOrganizationalUnits(config)

	// Create subject with production-like CN format (NAME:DOCUMENT)
	subject := pkix.Name{
		CommonName:         s.formatCommonName(config),
		OrganizationalUnit: orgUnits,
		Organization:       []string{"ICP-Brasil"},
		Country:            []string{"BR"},
	}

	// Build Certificate Policies extension manually (like production)
	certPoliciesExt, err := s.buildCertificatePoliciesExtension([]asn1.ObjectIdentifier{
		{2, 16, 76, 1, 2, 1, 133}, // ICP-Brasil PF policy
	})
	if err != nil {
		return nil, err
	}

	// Create template with all production-like extensions
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             config.ValidFrom,
		NotAfter:              config.ValidUntil,
		KeyUsage:              s.getX509KeyUsage(config),
		ExtKeyUsage:           s.getX509ExtKeyUsage(config),
		BasicConstraintsValid: true, // critical: true like production
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        s.caChain.IssuingCA.X509Cert.SubjectKeyId,

		// CRL Distribution Points (like production)
		CRLDistributionPoints: []string{
			"http://mock.icp-brasil.gov.br/repositorio/ac-mock-multipla/lcr/lcr-ac-mock-multipla.crl",
			"http://icp-brasil.mock.gov.br/repositorio/ac-mock-multipla/lcr/lcr-ac-mock-multipla.crl",
		},

		// Authority Information Access - CA Issuers (like production)
		IssuingCertificateURL: []string{
			"http://mock.icp-brasil.gov.br/repositorio/ac-mock-multipla/certificados/ac-mock-multipla.p7b",
		},

		// Add Certificate Policies as extra extension
		ExtraExtensions: []pkix.Extension{certPoliciesExt},
	}

	// Add DNS names if provided
	if len(config.DNSNames) > 0 {
		template.DNSNames = config.DNSNames
	}

	// Add email if provided
	if config.Email != "" {
		template.EmailAddresses = []string{config.Email}
	}

	return template, nil
}

// buildCertificatePoliciesExtension creates a Certificate Policies extension
// OID: 2.5.29.32
func (s *CertificateGeneratorService) buildCertificatePoliciesExtension(policyOIDs []asn1.ObjectIdentifier) (pkix.Extension, error) {
	// Certificate Policies OID
	certPoliciesOID := asn1.ObjectIdentifier{2, 5, 29, 32}

	// Build policy information sequence
	type policyInformation struct {
		PolicyIdentifier asn1.ObjectIdentifier
	}

	var policies []policyInformation
	for _, oid := range policyOIDs {
		policies = append(policies, policyInformation{PolicyIdentifier: oid})
	}

	// Encode the policies
	policyBytes, err := asn1.Marshal(policies)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       certPoliciesOID,
		Critical: false,
		Value:    policyBytes,
	}, nil
}

// buildOrganizationalUnits creates OUs similar to production certificates
func (s *CertificateGeneratorService) buildOrganizationalUnits(config domain.CertificateConfig) []string {
	var certTypeOU string
	switch config.Type {
	case domain.TypeA1:
		if config.PersonType == domain.PersonTypeIndividual {
			certTypeOU = "Certificado Digital PF A1"
		} else {
			certTypeOU = "Certificado Digital PJ A1"
		}
	case domain.TypeA3:
		if config.PersonType == domain.PersonTypeIndividual {
			certTypeOU = "Certificado Digital PF A3"
		} else {
			certTypeOU = "Certificado Digital PJ A3"
		}
	case domain.TypeA4:
		if config.PersonType == domain.PersonTypeIndividual {
			certTypeOU = "Certificado Digital PF A4"
		} else {
			certTypeOU = "Certificado Digital PJ A4"
		}
	default:
		certTypeOU = "Certificado Digital"
	}

	// Build OUs like production: [Type, Validation Method, CA CNPJ, Issuing CA Name]
	return []string{
		certTypeOU,
		"Videoconferencia",           // Validation method
		"00000000000000",             // Mock CA CNPJ
		"AC Mock Multipla",           // Issuing CA name
	}
}

// createExtensions creates the domain extensions based on the configuration
// These extensions match production ICP-Brasil certificates
func (s *CertificateGeneratorService) createExtensions(config domain.CertificateConfig) domain.Extensions {
	keyUsage := config.GetKeyUsage()

	return domain.Extensions{
		KeyUsage: keyUsage,
		BasicConstraints: domain.BasicConstraints{
			IsCA:     false,
			Critical: true, // Production uses critical: true
		},
		CertificatePolicies: []domain.CertificatePolicy{
			{
				OID:    "2.16.76.1.2.1.133", // ICP-Brasil PF policy OID like production
				CPSUri: "http://mock.icp-brasil.gov.br/repositorio/dpc",
			},
		},
		CRLDistributionPoints: []string{
			"http://mock.icp-brasil.gov.br/repositorio/ac-mock-multipla/lcr/lcr-ac-mock-multipla.crl",
			"http://icp-brasil.mock.gov.br/repositorio/ac-mock-multipla/lcr/lcr-ac-mock-multipla.crl",
		},
		SubjectAltName: domain.SubjectAltName{
			EmailAddresses: []string{config.Email},
			DNSNames:       config.DNSNames,
		},
		ExtendedKeyUsage: []domain.ExtendedKeyUsage{
			domain.ExtKeyUsageEmailProtection,
			domain.ExtKeyUsageClientAuth,
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
// Production certificates include both Email Protection and Client Authentication
func (s *CertificateGeneratorService) getX509ExtKeyUsage(config domain.CertificateConfig) []x509.ExtKeyUsage {
	switch config.Type {
	case domain.TypeA1, domain.TypeA3, domain.TypeA4:
		// Production includes Email Protection + Client Authentication
		return []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth}
	case domain.TypeSES, domain.TypeSEH:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	case domain.TypeAES, domain.TypeAEH:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth}
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
