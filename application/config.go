package application

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/icp-brasil-cert-generator/domain"
)

// Config represents the application configuration
type Config struct {
	Certificates []CertificateSettings `json:"certificates"`
	Output       OutputSettings        `json:"output"`
	Security     SecuritySettings      `json:"security"`
}

// CertificateSettings contains certificate-specific configuration
type CertificateSettings struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	PersonType   string   `json:"person_type"`
	SubjectName  string   `json:"subject_name"`
	Document     string   `json:"document"`
	Email        string   `json:"email"`
	ValidFrom    string   `json:"valid_from"`
	ValidUntil   string   `json:"valid_until"`
	KeySize      int      `json:"key_size"`
	Organization string   `json:"organization"`
	OrgUnit      string   `json:"org_unit"`
	Country      string   `json:"country"`
	DNSNames     []string `json:"dns_names"`
}

// OutputSettings contains output-specific configuration
type OutputSettings struct {
	Directory string   `json:"directory"`
	Formats   []string `json:"formats"`
}

// SecuritySettings contains security-specific configuration
type SecuritySettings struct {
	PFXPassword string `json:"pfx_password"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults for each certificate
	for i := range config.Certificates {
		cert := &config.Certificates[i]
		if cert.KeySize == 0 {
			cert.KeySize = 2048
		}
		if cert.Country == "" {
			cert.Country = "BR"
		}
		if cert.Organization == "" {
			cert.Organization = "ICP-Brasil"
		}
		if cert.OrgUnit == "" {
			cert.OrgUnit = "Mock Certificate"
		}
		if cert.Name == "" {
			cert.Name = fmt.Sprintf("cert_%d", i+1)
		}
	}

	// Set defaults for output
	if config.Output.Directory == "" {
		config.Output.Directory = "./output"
	}
	if len(config.Output.Formats) == 0 {
		config.Output.Formats = []string{"pem", "pfx"}
	}

	// Set defaults for security
	if config.Security.PFXPassword == "" {
		config.Security.PFXPassword = "changeme"
	}

	return &config, nil
}

// SaveConfig saves configuration to a JSON file
func SaveConfig(config *Config, filePath string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// ToCertificateConfigs converts the application config to domain certificate configs
func (c *Config) ToCertificateConfigs() ([]domain.CertificateConfig, error) {
	configs := make([]domain.CertificateConfig, len(c.Certificates))

	for i, cert := range c.Certificates {
		config, err := c.toCertificateConfig(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to convert certificate %d (%s): %w", i+1, cert.Name, err)
		}
		configs[i] = config
	}

	return configs, nil
}

// toCertificateConfig converts a single certificate setting to domain config
func (c *Config) toCertificateConfig(cert CertificateSettings) (domain.CertificateConfig, error) {
	// Parse certificate type
	certType, err := parseCertificateType(cert.Type)
	if err != nil {
		return domain.CertificateConfig{}, err
	}

	// Parse person type
	personType, err := parsePersonType(cert.PersonType)
	if err != nil {
		return domain.CertificateConfig{}, err
	}

	// Parse dates
	validFrom, err := parseDateTime(cert.ValidFrom)
	if err != nil {
		return domain.CertificateConfig{}, fmt.Errorf("invalid valid_from date: %w", err)
	}

	validUntil, err := parseDateTime(cert.ValidUntil)
	if err != nil {
		return domain.CertificateConfig{}, fmt.Errorf("invalid valid_until date: %w", err)
	}

	return domain.CertificateConfig{
		Type:         certType,
		PersonType:   personType,
		Name:         cert.SubjectName,
		Document:     cert.Document,
		ValidFrom:    validFrom,
		ValidUntil:   validUntil,
		KeySize:      cert.KeySize,
		Organization: cert.Organization,
		OrgUnit:      cert.OrgUnit,
		Country:      cert.Country,
		Email:        cert.Email,
		DNSNames:     cert.DNSNames,
	}, nil
}

// parseCertificateType parses a string certificate type
func parseCertificateType(typeStr string) (domain.CertificateType, error) {
	switch typeStr {
	case "A1":
		return domain.TypeA1, nil
	case "A3":
		return domain.TypeA3, nil
	case "A4":
		return domain.TypeA4, nil
	case "SE-S":
		return domain.TypeSES, nil
	case "SE-H":
		return domain.TypeSEH, nil
	case "AE-S":
		return domain.TypeAES, nil
	case "AE-H":
		return domain.TypeAEH, nil
	default:
		return "", fmt.Errorf("invalid certificate type: %s", typeStr)
	}
}

// parsePersonType parses a string person type
func parsePersonType(typeStr string) (domain.PersonType, error) {
	switch typeStr {
	case "individual":
		return domain.PersonTypeIndividual, nil
	case "legal_entity":
		return domain.PersonTypeLegalEntity, nil
	default:
		return "", fmt.Errorf("invalid person type: %s", typeStr)
	}
}

// parseDateTime parses a date string in the format "dd/MM/yyyy HH:mm:ss"
func parseDateTime(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, fmt.Errorf("date string is empty")
	}

	// Try parsing with time
	if t, err := time.Parse("02/01/2006 15:04:05", dateStr); err == nil {
		return t, nil
	}

	// Try parsing without time
	if t, err := time.Parse("02/01/2006", dateStr); err == nil {
		return t, nil
	}

	// Try ISO format as fallback
	if t, err := time.Parse("2006-01-02 15:04:05", dateStr); err == nil {
		return t, nil
	}

	if t, err := time.Parse("2006-01-02", dateStr); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("invalid date format, expected dd/MM/yyyy HH:mm:ss or dd/MM/yyyy")
}

// CreateDefaultConfig creates a default configuration with multiple certificates
func CreateDefaultConfig() *Config {
	return &Config{
		Certificates: []CertificateSettings{
			{
				Name:         "individual_cert",
				Type:         "A3",
				PersonType:   "individual",
				SubjectName:  "JOAO DA SILVA",
				Document:     "12345678901",
				Email:        "joao.silva@example.com",
				ValidFrom:    time.Now().Format("02/01/2006 15:04:05"),
				ValidUntil:   time.Now().AddDate(3, 0, 0).Format("02/01/2006 15:04:05"),
				KeySize:      2048,
				Organization: "ICP-Brasil",
				OrgUnit:      "Mock Certificate",
				Country:      "BR",
				DNSNames:     []string{},
			},
			{
				Name:         "company_cert",
				Type:         "A3",
				PersonType:   "legal_entity",
				SubjectName:  "EMPRESA EXEMPLO LTDA",
				Document:     "12345678000195",
				Email:        "contato@empresa.com.br",
				ValidFrom:    time.Now().Format("02/01/2006 15:04:05"),
				ValidUntil:   time.Now().AddDate(3, 0, 0).Format("02/01/2006 15:04:05"),
				KeySize:      2048,
				Organization: "ICP-Brasil",
				OrgUnit:      "Mock Certificate",
				Country:      "BR",
				DNSNames:     []string{"empresa.com.br", "www.empresa.com.br"},
			},
		},
		Output: OutputSettings{
			Directory: "./output",
			Formats:   []string{"pem", "pfx", "cert", "crt"},
		},
		Security: SecuritySettings{
			PFXPassword: "changeme",
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if len(c.Certificates) == 0 {
		return fmt.Errorf("at least one certificate configuration is required")
	}

	// Validate each certificate
	for i, cert := range c.Certificates {
		if err := c.validateCertificate(cert, i); err != nil {
			return fmt.Errorf("certificate %d (%s): %w", i+1, cert.Name, err)
		}
	}

	// Check for duplicate certificate names
	names := make(map[string]int)
	for i, cert := range c.Certificates {
		if prevIndex, exists := names[cert.Name]; exists {
			return fmt.Errorf("duplicate certificate name '%s' found at positions %d and %d", cert.Name, prevIndex+1, i+1)
		}
		names[cert.Name] = i
	}

	// Validate output settings
	if c.Output.Directory == "" {
		return fmt.Errorf("output directory is required")
	}

	if len(c.Output.Formats) == 0 {
		return fmt.Errorf("at least one output format is required")
	}

	// Validate output formats
	for _, format := range c.Output.Formats {
		if err := domain.ValidateOutputFormat(format); err != nil {
			return err
		}
	}

	// Validate security settings
	if c.Security.PFXPassword == "" {
		return fmt.Errorf("PFX password is required")
	}

	return nil
}

// validateCertificate validates a single certificate configuration
func (c *Config) validateCertificate(cert CertificateSettings, index int) error {
	if cert.Name == "" {
		return fmt.Errorf("certificate name is required")
	}

	if cert.Type == "" {
		return fmt.Errorf("certificate type is required")
	}

	if cert.PersonType == "" {
		return fmt.Errorf("person type is required")
	}

	if cert.SubjectName == "" {
		return fmt.Errorf("subject name is required")
	}

	if cert.Document == "" {
		return fmt.Errorf("document (CPF/CNPJ) is required")
	}

	if cert.ValidFrom == "" {
		return fmt.Errorf("valid from date is required")
	}

	if cert.ValidUntil == "" {
		return fmt.Errorf("valid until date is required")
	}

	if cert.KeySize < 2048 {
		return fmt.Errorf("key size must be at least 2048 bits")
	}

	return nil
}

// GetFormatsString returns a comma-separated string of output formats
func (c *Config) GetFormatsString() string {
	return strings.Join(c.Output.Formats, ", ")
}

// HasFormat checks if a specific format is enabled in the configuration
func (c *Config) HasFormat(format string) bool {
	for _, f := range c.Output.Formats {
		if strings.ToLower(f) == strings.ToLower(format) {
			return true
		}
	}
	return false
}

// GetCertificateOutputPath returns the output path for a specific certificate
func (c *Config) GetCertificateOutputPath(certName string) string {
	return filepath.Join(c.Output.Directory, certName)
}

// GetCertificateCount returns the number of certificates in the configuration
func (c *Config) GetCertificateCount() int {
	return len(c.Certificates)
}
