package tests

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/icp-brasil-cert-generator/application"
	"github.com/yourorg/icp-brasil-cert-generator/domain"
)

func TestConfigLoadAndSave(t *testing.T) {
	// Arrange
	config := application.CreateDefaultConfig()
	tempFile := "/tmp/test_config.json"
	defer os.Remove(tempFile)

	// Act - Save
	err := application.SaveConfig(config, tempFile)
	require.NoError(t, err)

	// Act - Load
	loadedConfig, err := application.LoadConfig(tempFile)
	require.NoError(t, err)

	// Assert
	assert.Equal(t, len(config.Certificates), len(loadedConfig.Certificates))
	assert.Equal(t, config.Certificates[0].Type, loadedConfig.Certificates[0].Type)
	assert.Equal(t, config.Certificates[0].PersonType, loadedConfig.Certificates[0].PersonType)
	assert.Equal(t, config.Certificates[0].SubjectName, loadedConfig.Certificates[0].SubjectName)
	assert.Equal(t, config.Certificates[0].Document, loadedConfig.Certificates[0].Document)
	assert.Equal(t, config.Certificates[0].KeySize, loadedConfig.Certificates[0].KeySize)
	assert.Equal(t, config.Output.Directory, loadedConfig.Output.Directory)
	assert.Equal(t, config.Security.PFXPassword, loadedConfig.Security.PFXPassword)
}

func TestConfigToCertificateConfigs(t *testing.T) {
	// Arrange
	config := &application.Config{
		Certificates: []application.CertificateSettings{
			{
				Name:         "test_cert",
				Type:         "A3",
				PersonType:   "individual",
				SubjectName:  "JOAO DA SILVA",
				Document:     "12345678901",
				Email:        "joao@example.com",
				ValidFrom:    "01/01/2024 00:00:00",
				ValidUntil:   "01/01/2027 23:59:59",
				KeySize:      2048,
				Organization: "ICP-Brasil",
				OrgUnit:      "Mock Certificate",
				Country:      "BR",
				DNSNames:     []string{"example.com"},
			},
		},
		Output: application.OutputSettings{
			Directory: "./output",
			Formats:   []string{"pem", "pfx"},
		},
		Security: application.SecuritySettings{
			PFXPassword: "password123",
		},
	}

	// Act
	domainConfigs, err := config.ToCertificateConfigs()

	// Assert
	require.NoError(t, err)
	require.Len(t, domainConfigs, 1)

	domainConfig := domainConfigs[0]
	assert.Equal(t, domain.TypeA3, domainConfig.Type)
	assert.Equal(t, domain.PersonTypeIndividual, domainConfig.PersonType)
	assert.Equal(t, "JOAO DA SILVA", domainConfig.Name)
	assert.Equal(t, "12345678901", domainConfig.Document)
	assert.Equal(t, "joao@example.com", domainConfig.Email)
	assert.Equal(t, 2048, domainConfig.KeySize)
	assert.Equal(t, "ICP-Brasil", domainConfig.Organization)
	assert.Equal(t, "Mock Certificate", domainConfig.OrgUnit)
	assert.Equal(t, "BR", domainConfig.Country)
	assert.Equal(t, []string{"example.com"}, domainConfig.DNSNames)
}

func TestConfigValidation(t *testing.T) {
	t.Run("Valid config", func(t *testing.T) {
		config := application.CreateDefaultConfig()
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid config - missing certificate type", func(t *testing.T) {
		config := application.CreateDefaultConfig()
		config.Certificates[0].Type = ""

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate type is required")
	})

	t.Run("Invalid config - missing subject name", func(t *testing.T) {
		config := application.CreateDefaultConfig()
		config.Certificates[0].SubjectName = ""

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "subject name is required")
	})

	t.Run("Invalid config - key size too small", func(t *testing.T) {
		config := application.CreateDefaultConfig()
		config.Certificates[0].KeySize = 1024

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key size must be at least 2048 bits")
	})

	t.Run("Invalid config - no certificates", func(t *testing.T) {
		config := application.CreateDefaultConfig()
		config.Certificates = []application.CertificateSettings{}

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one certificate configuration is required")
	})

	t.Run("Invalid config - duplicate certificate names", func(t *testing.T) {
		config := application.CreateDefaultConfig()
		config.Certificates = append(config.Certificates, config.Certificates[0])

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate certificate name")
	})

	t.Run("Invalid config - empty PFX password", func(t *testing.T) {
		config := application.CreateDefaultConfig()
		config.Security.PFXPassword = ""

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PFX password is required")
	})
}

func TestDateTimeParsing(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectError bool
	}{
		{"Valid date with time", "01/01/2024 12:30:45", false},
		{"Valid date without time", "01/01/2024", false},
		{"ISO format with time", "2024-01-01 12:30:45", false},
		{"ISO format without time", "2024-01-01", false},
		{"Invalid format", "2024/01/01", true},
		{"Empty string", "", true},
		{"Invalid date", "32/13/2024", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &application.Config{
				Certificates: []application.CertificateSettings{
					{
						Name:        "test_cert",
						Type:        "A3",
						PersonType:  "individual",
						SubjectName: "JOAO DA SILVA",
						Document:    "12345678901",
						ValidFrom:   tc.input,
						ValidUntil:  "01/01/2027 23:59:59",
						KeySize:     2048,
					},
				},
				Output: application.OutputSettings{
					Directory: "./output",
				},
				Security: application.SecuritySettings{
					PFXPassword: "password",
				},
			}

			_, err := config.ToCertificateConfigs()
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCertificateTypeParsing(t *testing.T) {
	testCases := []struct {
		input    string
		expected domain.CertificateType
		hasError bool
	}{
		{"A3", domain.TypeA3, false},
		{"A4", domain.TypeA4, false},
		{"SE-S", domain.TypeSES, false},
		{"SE-H", domain.TypeSEH, false},
		{"AE-S", domain.TypeAES, false},
		{"AE-H", domain.TypeAEH, false},
		{"INVALID", "", true},
		{"", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			config := &application.Config{
				Certificates: []application.CertificateSettings{
					{
						Name:        "test_cert",
						Type:        tc.input,
						PersonType:  "individual",
						SubjectName: "JOAO DA SILVA",
						Document:    "12345678901",
						ValidFrom:   "01/01/2024",
						ValidUntil:  "01/01/2027",
						KeySize:     2048,
					},
				},
				Output: application.OutputSettings{
					Directory: "./output",
				},
				Security: application.SecuritySettings{
					PFXPassword: "password",
				},
			}

			domainConfigs, err := config.ToCertificateConfigs()
			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, domainConfigs[0].Type)
			}
		})
	}
}

func TestPersonTypeParsing(t *testing.T) {
	testCases := []struct {
		input    string
		expected domain.PersonType
		hasError bool
	}{
		{"individual", domain.PersonTypeIndividual, false},
		{"legal_entity", domain.PersonTypeLegalEntity, false},
		{"INVALID", "", true},
		{"", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			config := &application.Config{
				Certificates: []application.CertificateSettings{
					{
						Name:        "test_cert",
						Type:        "A3",
						PersonType:  tc.input,
						SubjectName: "JOAO DA SILVA",
						Document:    "12345678901",
						ValidFrom:   "01/01/2024",
						ValidUntil:  "01/01/2027",
						KeySize:     2048,
					},
				},
				Output: application.OutputSettings{
					Directory: "./output",
				},
				Security: application.SecuritySettings{
					PFXPassword: "password",
				},
			}

			domainConfigs, err := config.ToCertificateConfigs()
			if tc.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, domainConfigs[0].PersonType)
			}
		})
	}
}

func TestDefaultConfigCreation(t *testing.T) {
	config := application.CreateDefaultConfig()

	// Test that we have multiple certificates by default
	assert.Len(t, config.Certificates, 2)

	// Test first certificate (individual)
	cert1 := config.Certificates[0]
	assert.Equal(t, "individual_cert", cert1.Name)
	assert.Equal(t, "A3", cert1.Type)
	assert.Equal(t, "individual", cert1.PersonType)
	assert.Equal(t, "JOAO DA SILVA", cert1.SubjectName)
	assert.Equal(t, "12345678901", cert1.Document)
	assert.Equal(t, 2048, cert1.KeySize)
	assert.Equal(t, "ICP-Brasil", cert1.Organization)
	assert.Equal(t, "BR", cert1.Country)

	// Test second certificate (company)
	cert2 := config.Certificates[1]
	assert.Equal(t, "company_cert", cert2.Name)
	assert.Equal(t, "A3", cert2.Type)
	assert.Equal(t, "legal_entity", cert2.PersonType)
	assert.Equal(t, "EMPRESA EXEMPLO LTDA", cert2.SubjectName)
	assert.Equal(t, "12345678000195", cert2.Document)
	assert.Equal(t, 2048, cert2.KeySize)
	assert.Equal(t, "ICP-Brasil", cert2.Organization)
	assert.Equal(t, "BR", cert2.Country)
	assert.Contains(t, cert2.DNSNames, "empresa.com.br")

	// Test output settings
	assert.Equal(t, "./output", config.Output.Directory)
	assert.Equal(t, []string{"pem", "pfx", "cert", "crt"}, config.Output.Formats)
	assert.Equal(t, "changeme", config.Security.PFXPassword)

	// Validate that dates are properly set for both certificates
	for i, cert := range config.Certificates {
		assert.NotEmpty(t, cert.ValidFrom, "Certificate %d should have ValidFrom", i)
		assert.NotEmpty(t, cert.ValidUntil, "Certificate %d should have ValidUntil", i)

		// Parse dates to ensure they're valid
		validFrom, err := time.Parse("02/01/2006 15:04:05", cert.ValidFrom)
		assert.NoError(t, err, "Certificate %d ValidFrom should be parseable", i)

		validUntil, err := time.Parse("02/01/2006 15:04:05", cert.ValidUntil)
		assert.NoError(t, err, "Certificate %d ValidUntil should be parseable", i)

		// Ensure valid until is after valid from
		assert.True(t, validUntil.After(validFrom), "Certificate %d ValidUntil should be after ValidFrom", i)
	}
}

func TestMultipleCertificateConfigs(t *testing.T) {
	config := &application.Config{
		Certificates: []application.CertificateSettings{
			{
				Name:        "cert1",
				Type:        "A3",
				PersonType:  "individual",
				SubjectName: "JOAO DA SILVA",
				Document:    "12345678901",
				ValidFrom:   "01/01/2024",
				ValidUntil:  "01/01/2027",
				KeySize:     2048,
			},
			{
				Name:        "cert2",
				Type:        "A4",
				PersonType:  "legal_entity",
				SubjectName: "EMPRESA LTDA",
				Document:    "12345678000195",
				ValidFrom:   "01/01/2024",
				ValidUntil:  "01/01/2027",
				KeySize:     4096,
			},
		},
		Output: application.OutputSettings{
			Directory: "./output",
			Formats:   []string{"pem"},
		},
		Security: application.SecuritySettings{
			PFXPassword: "password",
		},
	}

	// Act
	domainConfigs, err := config.ToCertificateConfigs()

	// Assert
	require.NoError(t, err)
	require.Len(t, domainConfigs, 2)

	// Test first certificate
	assert.Equal(t, domain.TypeA3, domainConfigs[0].Type)
	assert.Equal(t, domain.PersonTypeIndividual, domainConfigs[0].PersonType)
	assert.Equal(t, "JOAO DA SILVA", domainConfigs[0].Name)
	assert.Equal(t, 2048, domainConfigs[0].KeySize)

	// Test second certificate
	assert.Equal(t, domain.TypeA4, domainConfigs[1].Type)
	assert.Equal(t, domain.PersonTypeLegalEntity, domainConfigs[1].PersonType)
	assert.Equal(t, "EMPRESA LTDA", domainConfigs[1].Name)
	assert.Equal(t, 4096, domainConfigs[1].KeySize)
}
