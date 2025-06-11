package domain

import (
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"time"
)

// CertificateType represents the type of ICP Brasil certificate
type CertificateType string

const (
	TypeA1  CertificateType = "A1"   // Digital signature for individuals (software) - EXTINCT but supported for legacy
	TypeA3  CertificateType = "A3"   // Digital signature for individuals (hardware)
	TypeA4  CertificateType = "A4"   // Digital signature for individuals (hardware, higher security)
	TypeSES CertificateType = "SE-S" // Electronic seal for legal entities (software)
	TypeSEH CertificateType = "SE-H" // Electronic seal for legal entities (hardware)
	TypeAES CertificateType = "AE-S" // Specific applications (software)
	TypeAEH CertificateType = "AE-H" // Specific applications (hardware)
)

// PersonType represents whether the certificate is for an individual or legal entity
type PersonType string

const (
	PersonTypeIndividual  PersonType = "individual"
	PersonTypeLegalEntity PersonType = "legal_entity"
)

// OutputFormat represents the supported certificate output formats
type OutputFormat string

const (
	FormatPEM  OutputFormat = "pem"
	FormatPFX  OutputFormat = "pfx"
	FormatCERT OutputFormat = "cert"
	FormatCRT  OutputFormat = "crt"
)

// Certificate represents an ICP Brasil certificate with all required fields
type Certificate struct {
	Type           CertificateType
	PersonType     PersonType
	SubjectDN      SubjectDN
	ValidityPeriod ValidityPeriod
	Extensions     Extensions
	PrivateKey     *rsa.PrivateKey
	X509Cert       *x509.Certificate
}

// SubjectDN represents the Distinguished Name structure for ICP Brasil certificates
type SubjectDN struct {
	CommonName         string // CN - Full name or company name
	OrganizationalUnit string // OU - Department or subdivision
	Organization       string // O - Always "ICP-Brasil"
	Country            string // C - Always "BR"
	SerialNumber       string // serialNumber - CPF for individuals, CNPJ for legal entities
}

// ValidityPeriod represents the certificate validity period
type ValidityPeriod struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// Extensions represents X.509 v3 extensions specific to ICP Brasil
type Extensions struct {
	KeyUsage              KeyUsage
	BasicConstraints      BasicConstraints
	CertificatePolicies   []CertificatePolicy
	AuthorityKeyID        []byte
	SubjectKeyID          []byte
	CRLDistributionPoints []string
	SubjectAltName        SubjectAltName
	ExtendedKeyUsage      []ExtendedKeyUsage
}

// KeyUsage represents the Key Usage extension
type KeyUsage struct {
	DigitalSignature bool
	NonRepudiation   bool
	KeyEncipherment  bool
	KeyCertSign      bool
	CRLSign          bool
	Critical         bool
}

// BasicConstraints represents the Basic Constraints extension
type BasicConstraints struct {
	IsCA              bool
	PathLenConstraint int
	Critical          bool
}

// CertificatePolicy represents a certificate policy with OID
type CertificatePolicy struct {
	OID        string
	CPSUri     string
	UserNotice string
}

// SubjectAltName represents the Subject Alternative Name extension
type SubjectAltName struct {
	DNSNames       []string
	EmailAddresses []string
	OtherNames     []OtherName
}

// OtherName represents an otherName field in Subject Alternative Name
type OtherName struct {
	OID   string
	Value string
}

// ExtendedKeyUsage represents extended key usage purposes
type ExtendedKeyUsage string

const (
	ExtKeyUsageServerAuth      ExtendedKeyUsage = "1.3.6.1.5.5.7.3.1"
	ExtKeyUsageClientAuth      ExtendedKeyUsage = "1.3.6.1.5.5.7.3.2"
	ExtKeyUsageCodeSigning     ExtendedKeyUsage = "1.3.6.1.5.5.7.3.3"
	ExtKeyUsageEmailProtection ExtendedKeyUsage = "1.3.6.1.5.5.7.3.4"
	ExtKeyUsageTimeStamping    ExtendedKeyUsage = "1.3.6.1.5.5.7.3.8"
)

// CertificateRepository defines the interface for certificate persistence
type CertificateRepository interface {
	SavePEM(cert *Certificate, keyPath, certPath string) error
	SavePFX(cert *Certificate, path, password string) error
	SaveCERT(cert *Certificate, path string) error
	SaveCRT(cert *Certificate, path string) error
}

// CertificateGenerator defines the interface for certificate generation
type CertificateGenerator interface {
	Generate(config CertificateConfig) (*Certificate, error)
	GenerateCA() (*Certificate, error)
}

// CertificateConfig represents the configuration for certificate generation
type CertificateConfig struct {
	Type         CertificateType
	PersonType   PersonType
	Name         string
	Document     string // CPF or CNPJ
	ValidFrom    time.Time
	ValidUntil   time.Time
	KeySize      int
	Organization string
	OrgUnit      string
	Country      string
	Email        string
	DNSNames     []string
}

// Validate validates the certificate configuration
func (c CertificateConfig) Validate() error {
	if c.Type == "" {
		return NewValidationError("certificate type is required")
	}

	if c.PersonType == "" {
		return NewValidationError("person type is required")
	}

	if c.Name == "" {
		return NewValidationError("name is required")
	}

	if c.Document == "" {
		return NewValidationError("document (CPF/CNPJ) is required")
	}

	if c.ValidFrom.IsZero() {
		return NewValidationError("valid from date is required")
	}

	if c.ValidUntil.IsZero() {
		return NewValidationError("valid until date is required")
	}

	if c.ValidUntil.Before(c.ValidFrom) {
		return NewValidationError("valid until must be after valid from")
	}

	if c.KeySize < 2048 {
		return NewValidationError("key size must be at least 2048 bits")
	}

	return nil
}

// GetPolicyOID returns the appropriate policy OID for the certificate type
func (c CertificateConfig) GetPolicyOID() string {
	switch c.Type {
	case TypeA1:
		return "2.16.76.1.2.1.1" // A1 certificate policy (legacy)
	case TypeA3:
		return "2.16.76.1.2.3.1" // A3 certificate policy
	case TypeA4:
		return "2.16.76.1.2.4.1" // A4 certificate policy
	case TypeSES:
		return "2.16.76.1.2.201.1" // SE-S certificate policy
	case TypeSEH:
		return "2.16.76.1.2.202.1" // SE-H certificate policy
	case TypeAES:
		return "2.16.76.1.2.401.1" // AE-S certificate policy
	case TypeAEH:
		return "2.16.76.1.2.402.1" // AE-H certificate policy
	default:
		return "2.16.76.1.2.3.1" // Default to A3
	}
}

// GetKeyUsage returns the appropriate key usage for the certificate type
func (c CertificateConfig) GetKeyUsage() KeyUsage {
	switch c.Type {
	case TypeA1, TypeA3, TypeA4:
		return KeyUsage{
			DigitalSignature: true,
			NonRepudiation:   true,
			KeyEncipherment:  true,
			Critical:         true,
		}
	case TypeSES, TypeSEH:
		return KeyUsage{
			DigitalSignature: true,
			NonRepudiation:   true,
			Critical:         true,
		}
	case TypeAES, TypeAEH:
		return KeyUsage{
			DigitalSignature: true,
			KeyEncipherment:  true,
			Critical:         true,
		}
	default:
		return KeyUsage{
			DigitalSignature: true,
			NonRepudiation:   true,
			Critical:         true,
		}
	}
}

// ValidateOutputFormat validates if the given format is supported
func ValidateOutputFormat(format string) error {
	switch OutputFormat(strings.ToLower(format)) {
	case FormatPEM, FormatPFX, FormatCERT, FormatCRT:
		return nil
	default:
		return NewValidationError("unsupported output format: " + format + ". Supported formats: pem, pfx, cert, crt")
	}
}

// GetSupportedFormats returns a list of all supported output formats
func GetSupportedFormats() []string {
	return []string{string(FormatPEM), string(FormatPFX), string(FormatCERT), string(FormatCRT)}
}
