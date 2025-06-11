package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/icp-brasil-cert-generator/application"
	"github.com/yourorg/icp-brasil-cert-generator/domain"
	"github.com/yourorg/icp-brasil-cert-generator/infrastructure"
)

func TestCertificateFormats(t *testing.T) {
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

	// Create temporary directory for test output
	tempDir, err := os.MkdirTemp("", "cert_test_")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Act - Generate certificate
	cert, err := generator.Generate(config)
	require.NoError(t, err)

	// Test all formats
	formats := []string{"pem", "pfx", "cert", "crt"}
	err = generator.SaveCertificatesWithFormats(cert, tempDir, "testpassword", formats)
	require.NoError(t, err)

	// Assert - Check that all files were created
	t.Run("PEM format files exist", func(t *testing.T) {
		certPath := filepath.Join(tempDir, "certificate.crt")
		keyPath := filepath.Join(tempDir, "certificate.key")

		assert.FileExists(t, certPath)
		assert.FileExists(t, keyPath)

		// Check file sizes are reasonable
		certInfo, err := os.Stat(certPath)
		require.NoError(t, err)
		assert.Greater(t, certInfo.Size(), int64(100))

		keyInfo, err := os.Stat(keyPath)
		require.NoError(t, err)
		assert.Greater(t, keyInfo.Size(), int64(100))
	})

	t.Run("PFX format file exists", func(t *testing.T) {
		pfxPath := filepath.Join(tempDir, "certificate.pfx")

		assert.FileExists(t, pfxPath)

		// Check file size is reasonable
		pfxInfo, err := os.Stat(pfxPath)
		require.NoError(t, err)
		assert.Greater(t, pfxInfo.Size(), int64(100))
	})

	t.Run("CERT format file exists", func(t *testing.T) {
		certPath := filepath.Join(tempDir, "certificate.cert")

		assert.FileExists(t, certPath)

		// Check file size is reasonable (DER format should be smaller than PEM)
		certInfo, err := os.Stat(certPath)
		require.NoError(t, err)
		assert.Greater(t, certInfo.Size(), int64(100))
		assert.Less(t, certInfo.Size(), int64(5000)) // DER should be compact
	})

	t.Run("CRT format file exists", func(t *testing.T) {
		crtPath := filepath.Join(tempDir, "certificate.crt")

		assert.FileExists(t, crtPath)

		// Check file size is reasonable (DER format should be smaller than PEM)
		crtInfo, err := os.Stat(crtPath)
		require.NoError(t, err)
		assert.Greater(t, crtInfo.Size(), int64(100))
		assert.Less(t, crtInfo.Size(), int64(5000)) // DER should be compact
	})
}

func TestDERCertificateLoading(t *testing.T) {
	// Arrange
	repository := infrastructure.NewFileRepository()
	generator := application.NewCertificateGeneratorService(repository)

	config := domain.CertificateConfig{
		Type:         domain.TypeA3,
		PersonType:   domain.PersonTypeIndividual,
		Name:         "MARIA DOS SANTOS",
		Document:     "98765432100",
		ValidFrom:    time.Now(),
		ValidUntil:   time.Now().AddDate(2, 0, 0),
		KeySize:      2048,
		Organization: "ICP-Brasil",
		OrgUnit:      "Test Certificate",
		Country:      "BR",
		Email:        "maria.santos@example.com",
	}

	// Create temporary directory for test output
	tempDir, err := os.MkdirTemp("", "der_test_")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Act - Generate and save certificate in DER formats
	cert, err := generator.Generate(config)
	require.NoError(t, err)

	certPath := filepath.Join(tempDir, "test.cert")
	crtPath := filepath.Join(tempDir, "test.crt")

	err = repository.SaveCERT(cert, certPath)
	require.NoError(t, err)

	err = repository.SaveCRT(cert, crtPath)
	require.NoError(t, err)

	// Assert - Load and verify DER certificates
	t.Run("Load CERT format", func(t *testing.T) {
		loadedCert, err := repository.LoadCertificateDER(certPath)
		require.NoError(t, err)

		assert.Equal(t, cert.X509Cert.Subject.CommonName, loadedCert.Subject.CommonName)
		assert.Equal(t, cert.X509Cert.Subject.SerialNumber, loadedCert.Subject.SerialNumber)
		assert.Equal(t, cert.X509Cert.NotBefore.Unix(), loadedCert.NotBefore.Unix())
		assert.Equal(t, cert.X509Cert.NotAfter.Unix(), loadedCert.NotAfter.Unix())
	})

	t.Run("Load CRT format", func(t *testing.T) {
		loadedCert, err := repository.LoadCertificateDER(crtPath)
		require.NoError(t, err)

		assert.Equal(t, cert.X509Cert.Subject.CommonName, loadedCert.Subject.CommonName)
		assert.Equal(t, cert.X509Cert.Subject.SerialNumber, loadedCert.Subject.SerialNumber)
		assert.Equal(t, cert.X509Cert.NotBefore.Unix(), loadedCert.NotBefore.Unix())
		assert.Equal(t, cert.X509Cert.NotAfter.Unix(), loadedCert.NotAfter.Unix())
	})
}

func TestOutputFormatValidation(t *testing.T) {
	testCases := []struct {
		name        string
		format      string
		expectError bool
	}{
		{"Valid PEM format", "pem", false},
		{"Valid PFX format", "pfx", false},
		{"Valid CERT format", "cert", false},
		{"Valid CRT format", "crt", false},
		{"Valid PEM format uppercase", "PEM", false},
		{"Valid PFX format uppercase", "PFX", false},
		{"Valid CERT format uppercase", "CERT", false},
		{"Valid CRT format uppercase", "CRT", false},
		{"Invalid format", "invalid", true},
		{"Empty format", "", true},
		{"P12 format (not supported)", "p12", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := domain.ValidateOutputFormat(tc.format)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetSupportedFormats(t *testing.T) {
	formats := domain.GetSupportedFormats()

	assert.Len(t, formats, 4)
	assert.Contains(t, formats, "pem")
	assert.Contains(t, formats, "pfx")
	assert.Contains(t, formats, "cert")
	assert.Contains(t, formats, "crt")
}
