package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yourorg/icp-brasil-cert-generator/domain"
)

func TestCPFValidation(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		valid   bool
		cleaned string
	}{
		{"Valid CPF with dots and dash", "123.456.789-09", true, "12345678909"},
		{"Valid CPF without formatting", "12345678909", true, "12345678909"},
		{"Valid CPF with spaces", "123 456 789 09", true, "12345678909"},
		{"Invalid CPF - all zeros", "00000000000", false, ""},
		{"Invalid CPF - all same digits", "11111111111", false, ""},
		{"Invalid CPF - wrong check digit", "12345678901", false, ""},
		{"Invalid CPF - too short", "123456789", false, ""},
		{"Invalid CPF - too long", "123456789012", false, ""},
		{"Invalid CPF - letters", "123abc78909", false, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cpf, err := domain.NewCPF(tc.input)

			if tc.valid {
				assert.NoError(t, err)
				assert.Equal(t, tc.cleaned, cpf.String())
			} else {
				assert.Error(t, err)
				assert.IsType(t, domain.ValidationError{}, err)
			}
		})
	}
}

func TestCPFFormatting(t *testing.T) {
	cpf, err := domain.NewCPF("12345678909")
	assert.NoError(t, err)

	assert.Equal(t, "12345678909", cpf.String())
	assert.Equal(t, "123.456.789-09", cpf.Formatted())
}

func TestCNPJValidation(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		valid   bool
		cleaned string
	}{
		{"Valid CNPJ with formatting", "11.222.333/0001-81", true, "11222333000181"},
		{"Valid CNPJ without formatting", "11222333000181", true, "11222333000181"},
		{"Valid CNPJ with spaces", "11 222 333 0001 81", true, "11222333000181"},
		{"Invalid CNPJ - all zeros", "00000000000000", false, ""},
		{"Invalid CNPJ - all same digits", "11111111111111", false, ""},
		{"Invalid CNPJ - wrong check digit", "11222333000180", false, ""},
		{"Invalid CNPJ - too short", "1122233300018", false, ""},
		{"Invalid CNPJ - too long", "112223330001811", false, ""},
		{"Invalid CNPJ - letters", "11222abc000181", false, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cnpj, err := domain.NewCNPJ(tc.input)

			if tc.valid {
				assert.NoError(t, err)
				assert.Equal(t, tc.cleaned, cnpj.String())
			} else {
				assert.Error(t, err)
				assert.IsType(t, domain.ValidationError{}, err)
			}
		})
	}
}

func TestCNPJFormatting(t *testing.T) {
	cnpj, err := domain.NewCNPJ("11222333000181")
	assert.NoError(t, err)

	assert.Equal(t, "11222333000181", cnpj.String())
	assert.Equal(t, "11.222.333/0001-81", cnpj.Formatted())
}

func TestNameSanitization(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"Simple name", "João Silva", "JOAO SILVA"},
		{"Name with accents", "José María", "JOSE MARIA"},
		{"Name with cedilla", "Conceição", "CONCEICAO"},
		{"Name with special chars", "João@#$Silva", "JOAOSILVA"},
		{"Name with numbers", "João Silva 123", "JOAO SILVA 123"},
		{"Multiple spaces", "João    Silva", "JOAO SILVA"},
		{"Leading/trailing spaces", "  João Silva  ", "JOAO SILVA"},
		{"All accented characters", "àáâãäèéêëìíîïòóôõöùúûüç", "AAAAAEEEEIIIIOOOOOUUUUC"},
		{"Mixed case", "jOãO sIlVa", "JOAO SILVA"},
		{"Empty string", "", ""},
		{"Only spaces", "   ", ""},
		{"Only special chars", "@#$%^&*()", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := domain.SanitizeName(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestFieldLengthValidation(t *testing.T) {
	testCases := []struct {
		name      string
		field     string
		value     string
		maxLength int
		expectErr bool
	}{
		{"Valid length", "name", "João Silva", 20, false},
		{"Exact max length", "name", "1234567890", 10, false},
		{"Exceeds max length", "name", "João Silva Santos", 10, true},
		{"Empty value", "name", "", 10, false},
		{"Zero max length", "name", "João", 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := domain.ValidateFieldLength(tc.field, tc.value, tc.maxLength)

			if tc.expectErr {
				assert.Error(t, err)
				assert.IsType(t, domain.ValidationError{}, err)
				assert.Contains(t, err.Error(), tc.field)
				assert.Contains(t, err.Error(), "exceeds maximum length")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDomainErrors(t *testing.T) {
	t.Run("ValidationError", func(t *testing.T) {
		err := domain.NewValidationError("test validation error")
		assert.Equal(t, "ValidationError: test validation error", err.Error())
		assert.Equal(t, "ValidationError", err.Type)
		assert.Equal(t, "test validation error", err.Message)
		assert.Nil(t, err.Cause)
	})

	t.Run("ValidationError with cause", func(t *testing.T) {
		cause := assert.AnError
		err := domain.NewValidationErrorWithCause("test validation error", cause)
		assert.Contains(t, err.Error(), "test validation error")
		assert.Contains(t, err.Error(), "caused by")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("GenerationError", func(t *testing.T) {
		err := domain.NewGenerationError("test generation error")
		assert.Equal(t, "GenerationError: test generation error", err.Error())
		assert.Equal(t, "GenerationError", err.Type)
		assert.Equal(t, "test generation error", err.Message)
		assert.Nil(t, err.Cause)
	})

	t.Run("PersistenceError", func(t *testing.T) {
		err := domain.NewPersistenceError("test persistence error")
		assert.Equal(t, "PersistenceError: test persistence error", err.Error())
		assert.Equal(t, "PersistenceError", err.Type)
		assert.Equal(t, "test persistence error", err.Message)
		assert.Nil(t, err.Cause)
	})
}

func TestCertificateConfigPolicyOIDs(t *testing.T) {
	testCases := []struct {
		certType    domain.CertificateType
		expectedOID string
	}{
		{domain.TypeA3, "2.16.76.1.2.3.1"},
		{domain.TypeA4, "2.16.76.1.2.4.1"},
		{domain.TypeSES, "2.16.76.1.2.201.1"},
		{domain.TypeSEH, "2.16.76.1.2.202.1"},
		{domain.TypeAES, "2.16.76.1.2.401.1"},
		{domain.TypeAEH, "2.16.76.1.2.402.1"},
	}

	for _, tc := range testCases {
		t.Run(string(tc.certType), func(t *testing.T) {
			config := domain.CertificateConfig{Type: tc.certType}
			oid := config.GetPolicyOID()
			assert.Equal(t, tc.expectedOID, oid)
		})
	}
}

func TestCertificateConfigKeyUsage(t *testing.T) {
	testCases := []struct {
		certType           domain.CertificateType
		expectedDigitalSig bool
		expectedNonRepud   bool
		expectedKeyEnc     bool
	}{
		{domain.TypeA3, true, true, true},
		{domain.TypeA4, true, true, true},
		{domain.TypeSES, true, true, false},
		{domain.TypeSEH, true, true, false},
		{domain.TypeAES, true, false, true},
		{domain.TypeAEH, true, false, true},
	}

	for _, tc := range testCases {
		t.Run(string(tc.certType), func(t *testing.T) {
			config := domain.CertificateConfig{Type: tc.certType}
			keyUsage := config.GetKeyUsage()

			assert.Equal(t, tc.expectedDigitalSig, keyUsage.DigitalSignature)
			assert.Equal(t, tc.expectedNonRepud, keyUsage.NonRepudiation)
			assert.Equal(t, tc.expectedKeyEnc, keyUsage.KeyEncipherment)
			assert.True(t, keyUsage.Critical)
		})
	}
}
