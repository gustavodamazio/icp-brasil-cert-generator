package tests

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/icp-brasil-cert-generator/application"
	"github.com/yourorg/icp-brasil-cert-generator/domain"
	"github.com/yourorg/icp-brasil-cert-generator/infrastructure"
)

func TestCertificateGeneration(t *testing.T) {
	// Arrange
	repository := infrastructure.NewFileRepository()
	generator := application.NewCertificateGeneratorService(repository)

	config := domain.CertificateConfig{
		Type:         domain.TypeA3,
		PersonType:   domain.PersonTypeIndividual,
		Name:         "JOAO DA SILVA",
		Document:     "12345678901",
		ValidFrom:    time.Now(),
		ValidUntil:   time.Now().AddDate(3, 0, 0),
		KeySize:      2048,
		Organization: "ICP-Brasil",
		OrgUnit:      "Mock Certificate",
		Country:      "BR",
		Email:        "joao.silva@example.com",
	}

	// Act
	cert, err := generator.Generate(config)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, domain.TypeA3, cert.Type)
	assert.Equal(t, domain.PersonTypeIndividual, cert.PersonType)
	assert.Equal(t, "JOAO DA SILVA", cert.SubjectDN.CommonName)
	assert.Equal(t, "12345678901", cert.SubjectDN.SerialNumber)
	assert.Equal(t, "ICP-Brasil", cert.SubjectDN.Organization)
	assert.Equal(t, "BR", cert.SubjectDN.Country)
	assert.NotNil(t, cert.PrivateKey)
	assert.NotNil(t, cert.X509Cert)
}

func TestCertificateGenerationWithInvalidConfig(t *testing.T) {
	// Arrange
	repository := infrastructure.NewFileRepository()
	generator := application.NewCertificateGeneratorService(repository)

	config := domain.CertificateConfig{
		// Missing required fields
		Type: domain.TypeA3,
	}

	// Act
	cert, err := generator.Generate(config)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.IsType(t, domain.ValidationError{}, err)
}

func TestCAGeneration(t *testing.T) {
	// Arrange
	repository := infrastructure.NewFileRepository()
	generator := application.NewCertificateGeneratorService(repository)

	// Act
	ca, err := generator.GenerateCA()

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, ca)
	assert.Equal(t, "ICP-Brasil Mock CA", ca.SubjectDN.CommonName)
	assert.Equal(t, "ICP-Brasil", ca.SubjectDN.Organization)
	assert.Equal(t, "BR", ca.SubjectDN.Country)
	assert.NotNil(t, ca.PrivateKey)
	assert.NotNil(t, ca.X509Cert)
	assert.True(t, ca.X509Cert.IsCA)
}

func TestCertificateTypes(t *testing.T) {
	repository := infrastructure.NewFileRepository()
	generator := application.NewCertificateGeneratorService(repository)

	testCases := []struct {
		name     string
		certType domain.CertificateType
		expected string
	}{
		{"A3 Certificate", domain.TypeA3, "2.16.76.1.2.3.1"},
		{"A4 Certificate", domain.TypeA4, "2.16.76.1.2.4.1"},
		{"SE-S Certificate", domain.TypeSES, "2.16.76.1.2.201.1"},
		{"SE-H Certificate", domain.TypeSEH, "2.16.76.1.2.202.1"},
		{"AE-S Certificate", domain.TypeAES, "2.16.76.1.2.401.1"},
		{"AE-H Certificate", domain.TypeAEH, "2.16.76.1.2.402.1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			config := domain.CertificateConfig{
				Type:         tc.certType,
				PersonType:   domain.PersonTypeIndividual,
				Name:         "JOAO DA SILVA",
				Document:     "12345678901",
				ValidFrom:    time.Now(),
				ValidUntil:   time.Now().AddDate(1, 0, 0),
				KeySize:      2048,
				Organization: "ICP-Brasil",
				OrgUnit:      "Mock Certificate",
				Country:      "BR",
			}

			// Act
			cert, err := generator.Generate(config)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, tc.certType, cert.Type)
			assert.Equal(t, tc.expected, config.GetPolicyOID())
		})
	}
}

func TestKeyUsageForDifferentCertificateTypes(t *testing.T) {
	testCases := []struct {
		name               string
		certType           domain.CertificateType
		expectedDigitalSig bool
		expectedNonRepud   bool
		expectedKeyEnc     bool
	}{
		{"A3", domain.TypeA3, true, true, true},
		{"A4", domain.TypeA4, true, true, true},
		{"SE-S", domain.TypeSES, true, true, false},
		{"SE-H", domain.TypeSEH, true, true, false},
		{"AE-S", domain.TypeAES, true, false, true},
		{"AE-H", domain.TypeAEH, true, false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			config := domain.CertificateConfig{
				Type: tc.certType,
			}

			// Act
			keyUsage := config.GetKeyUsage()

			// Assert
			assert.Equal(t, tc.expectedDigitalSig, keyUsage.DigitalSignature)
			assert.Equal(t, tc.expectedNonRepud, keyUsage.NonRepudiation)
			assert.Equal(t, tc.expectedKeyEnc, keyUsage.KeyEncipherment)
			assert.True(t, keyUsage.Critical)
		})
	}
}

func TestMultipleCertificateGeneration(t *testing.T) {
	// Arrange
	repository := infrastructure.NewFileRepository()
	generator := application.NewCertificateGeneratorService(repository)

	config := &application.Config{
		Certificates: []application.CertificateSettings{
			{
				Name:        "individual_cert",
				Type:        "A3",
				PersonType:  "individual",
				SubjectName: "JOAO DA SILVA",
				Document:    "12345678901",
				Email:       "joao@example.com",
				ValidFrom:   "01/01/2024 00:00:00",
				ValidUntil:  "01/01/2027 23:59:59",
				KeySize:     2048,
			},
			{
				Name:        "company_cert",
				Type:        "A4",
				PersonType:  "legal_entity",
				SubjectName: "EMPRESA LTDA",
				Document:    "12345678000195",
				Email:       "empresa@example.com",
				ValidFrom:   "01/01/2024 00:00:00",
				ValidUntil:  "01/01/2027 23:59:59",
				KeySize:     4096,
				DNSNames:    []string{"empresa.com.br"},
			},
		},
		Output: application.OutputSettings{
			Directory: "./test-output",
			Formats:   []string{"pem", "pfx"},
		},
		Security: application.SecuritySettings{
			PFXPassword: "testpassword",
		},
	}

	// Clean up before test
	os.RemoveAll("./test-output")
	defer os.RemoveAll("./test-output")

	// Act
	certificates, err := generator.GenerateMultiple(config)

	// Assert
	require.NoError(t, err)
	require.Len(t, certificates, 2)

	// Test first certificate (individual)
	cert1 := certificates[0]
	assert.Equal(t, domain.TypeA3, cert1.Type)
	assert.Equal(t, domain.PersonTypeIndividual, cert1.PersonType)
	assert.Equal(t, "JOAO DA SILVA", cert1.SubjectDN.CommonName)
	assert.Equal(t, "12345678901", cert1.SubjectDN.SerialNumber)
	assert.NotNil(t, cert1.PrivateKey)
	assert.NotNil(t, cert1.X509Cert)

	// Test second certificate (company)
	cert2 := certificates[1]
	assert.Equal(t, domain.TypeA4, cert2.Type)
	assert.Equal(t, domain.PersonTypeLegalEntity, cert2.PersonType)
	assert.Equal(t, "EMPRESA LTDA", cert2.SubjectDN.CommonName)
	assert.Equal(t, "12345678000195", cert2.SubjectDN.SerialNumber)
	assert.NotNil(t, cert2.PrivateKey)
	assert.NotNil(t, cert2.X509Cert)
}

func TestSaveMultipleCertificates(t *testing.T) {
	// Arrange
	repository := infrastructure.NewFileRepository()
	generator := application.NewCertificateGeneratorService(repository)

	config := &application.Config{
		Certificates: []application.CertificateSettings{
			{
				Name:        "test_cert_1",
				Type:        "A3",
				PersonType:  "individual",
				SubjectName: "TESTE UM",
				Document:    "11111111111",
				ValidFrom:   "01/01/2024",
				ValidUntil:  "01/01/2027",
				KeySize:     2048,
			},
			{
				Name:        "test_cert_2",
				Type:        "A3",
				PersonType:  "individual",
				SubjectName: "TESTE DOIS",
				Document:    "22222222222",
				ValidFrom:   "01/01/2024",
				ValidUntil:  "01/01/2027",
				KeySize:     2048,
			},
		},
		Output: application.OutputSettings{
			Directory: "./test-multi-output",
			Formats:   []string{"pem", "pfx"},
		},
		Security: application.SecuritySettings{
			PFXPassword: "testpass",
		},
	}

	// Clean up before and after test
	os.RemoveAll("./test-multi-output")
	defer os.RemoveAll("./test-multi-output")

	// Generate certificates
	certificates, err := generator.GenerateMultiple(config)
	require.NoError(t, err)

	// Act - Save certificates
	err = generator.SaveMultipleCertificates(certificates, config)

	// Assert
	require.NoError(t, err)

	// Check that directories were created
	assert.DirExists(t, "./test-multi-output/test_cert_1")
	assert.DirExists(t, "./test-multi-output/test_cert_2")

	// Check that files were created for first certificate
	assert.FileExists(t, "./test-multi-output/test_cert_1/certificate.crt")
	assert.FileExists(t, "./test-multi-output/test_cert_1/certificate.key")
	assert.FileExists(t, "./test-multi-output/test_cert_1/certificate.pfx")

	// Check that files were created for second certificate
	assert.FileExists(t, "./test-multi-output/test_cert_2/certificate.crt")
	assert.FileExists(t, "./test-multi-output/test_cert_2/certificate.key")
	assert.FileExists(t, "./test-multi-output/test_cert_2/certificate.pfx")
}

func TestMultipleCertificateGenerationWithInvalidConfig(t *testing.T) {
	// Arrange
	repository := infrastructure.NewFileRepository()
	generator := application.NewCertificateGeneratorService(repository)

	config := &application.Config{
		Certificates: []application.CertificateSettings{
			{
				Name:        "valid_cert",
				Type:        "A3",
				PersonType:  "individual",
				SubjectName: "VALID CERT",
				Document:    "12345678901",
				ValidFrom:   "01/01/2024",
				ValidUntil:  "01/01/2027",
				KeySize:     2048,
			},
			{
				Name:        "invalid_cert",
				Type:        "INVALID",
				PersonType:  "individual",
				SubjectName: "INVALID CERT",
				Document:    "12345678901",
				ValidFrom:   "01/01/2024",
				ValidUntil:  "01/01/2027",
				KeySize:     2048,
			},
		},
		Output: application.OutputSettings{
			Directory: "./test-output",
			Formats:   []string{"pem"},
		},
		Security: application.SecuritySettings{
			PFXPassword: "testpass",
		},
	}

	// Act
	certificates, err := generator.GenerateMultiple(config)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, certificates)
	assert.Contains(t, err.Error(), "invalid certificate type")
}

func TestConfigGetCertificateOutputPath(t *testing.T) {
	config := &application.Config{
		Output: application.OutputSettings{
			Directory: "./base-output",
		},
	}

	path := config.GetCertificateOutputPath("test_cert")
	assert.Equal(t, "base-output/test_cert", path)
}

func TestConfigGetCertificateCount(t *testing.T) {
	config := &application.Config{
		Certificates: []application.CertificateSettings{
			{Name: "cert1"},
			{Name: "cert2"},
			{Name: "cert3"},
		},
	}

	count := config.GetCertificateCount()
	assert.Equal(t, 3, count)
}
