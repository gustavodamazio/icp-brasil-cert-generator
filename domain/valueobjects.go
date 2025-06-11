package domain

import (
	"regexp"
	"strconv"
	"strings"
)

// CPF represents a Brazilian CPF (Cadastro de Pessoas Físicas)
type CPF struct {
	value string
}

// NewCPF creates a new CPF value object
func NewCPF(value string) (CPF, error) {
	cleaned := cleanDocument(value)
	if !isValidCPF(cleaned) {
		return CPF{}, NewValidationError("invalid CPF format")
	}
	return CPF{value: cleaned}, nil
}

// String returns the CPF as a string
func (c CPF) String() string {
	return c.value
}

// Formatted returns the CPF in formatted form (XXX.XXX.XXX-XX)
func (c CPF) Formatted() string {
	if len(c.value) != 11 {
		return c.value
	}
	return c.value[:3] + "." + c.value[3:6] + "." + c.value[6:9] + "-" + c.value[9:]
}

// CNPJ represents a Brazilian CNPJ (Cadastro Nacional da Pessoa Jurídica)
type CNPJ struct {
	value string
}

// NewCNPJ creates a new CNPJ value object
func NewCNPJ(value string) (CNPJ, error) {
	cleaned := cleanDocument(value)
	if !isValidCNPJ(cleaned) {
		return CNPJ{}, NewValidationError("invalid CNPJ format")
	}
	return CNPJ{value: cleaned}, nil
}

// String returns the CNPJ as a string
func (c CNPJ) String() string {
	return c.value
}

// Formatted returns the CNPJ in formatted form (XX.XXX.XXX/XXXX-XX)
func (c CNPJ) Formatted() string {
	if len(c.value) != 14 {
		return c.value
	}
	return c.value[:2] + "." + c.value[2:5] + "." + c.value[5:8] + "/" + c.value[8:12] + "-" + c.value[12:]
}

// cleanDocument removes non-numeric characters from a document
func cleanDocument(doc string) string {
	re := regexp.MustCompile(`[^\d]`)
	return re.ReplaceAllString(doc, "")
}

// isValidCPF validates a CPF using the check digit algorithm
func isValidCPF(cpf string) bool {
	if len(cpf) != 11 {
		return false
	}

	// Check for known invalid CPFs (all same digits)
	if cpf == "00000000000" || cpf == "11111111111" || cpf == "22222222222" ||
		cpf == "33333333333" || cpf == "44444444444" || cpf == "55555555555" ||
		cpf == "66666666666" || cpf == "77777777777" || cpf == "88888888888" ||
		cpf == "99999999999" {
		return false
	}

	// Validate first check digit
	sum := 0
	for i := 0; i < 9; i++ {
		digit, _ := strconv.Atoi(string(cpf[i]))
		sum += digit * (10 - i)
	}
	remainder := sum % 11
	checkDigit1 := 0
	if remainder >= 2 {
		checkDigit1 = 11 - remainder
	}

	if checkDigit1 != int(cpf[9]-'0') {
		return false
	}

	// Validate second check digit
	sum = 0
	for i := 0; i < 10; i++ {
		digit, _ := strconv.Atoi(string(cpf[i]))
		sum += digit * (11 - i)
	}
	remainder = sum % 11
	checkDigit2 := 0
	if remainder >= 2 {
		checkDigit2 = 11 - remainder
	}

	return checkDigit2 == int(cpf[10]-'0')
}

// isValidCNPJ validates a CNPJ using the check digit algorithm
func isValidCNPJ(cnpj string) bool {
	if len(cnpj) != 14 {
		return false
	}

	// Check for known invalid CNPJs (all same digits)
	if cnpj == "00000000000000" || cnpj == "11111111111111" || cnpj == "22222222222222" ||
		cnpj == "33333333333333" || cnpj == "44444444444444" || cnpj == "55555555555555" ||
		cnpj == "66666666666666" || cnpj == "77777777777777" || cnpj == "88888888888888" ||
		cnpj == "99999999999999" {
		return false
	}

	// Validate first check digit
	weights1 := []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 12; i++ {
		digit, _ := strconv.Atoi(string(cnpj[i]))
		sum += digit * weights1[i]
	}
	remainder := sum % 11
	checkDigit1 := 0
	if remainder >= 2 {
		checkDigit1 = 11 - remainder
	}

	if checkDigit1 != int(cnpj[12]-'0') {
		return false
	}

	// Validate second check digit
	weights2 := []int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	sum = 0
	for i := 0; i < 13; i++ {
		digit, _ := strconv.Atoi(string(cnpj[i]))
		sum += digit * weights2[i]
	}
	remainder = sum % 11
	checkDigit2 := 0
	if remainder >= 2 {
		checkDigit2 = 11 - remainder
	}

	return checkDigit2 == int(cnpj[13]-'0')
}

// SanitizeName sanitizes a name according to ICP Brasil standards
// Removes accents, converts ç to c, and ensures only A-Z, 0-9 characters
func SanitizeName(name string) string {
	// Convert to uppercase
	name = strings.ToUpper(name)

	// Replace accented characters
	replacements := map[string]string{
		"Á": "A", "À": "A", "Â": "A", "Ã": "A", "Ä": "A",
		"É": "E", "È": "E", "Ê": "E", "Ë": "E",
		"Í": "I", "Ì": "I", "Î": "I", "Ï": "I",
		"Ó": "O", "Ò": "O", "Ô": "O", "Õ": "O", "Ö": "O",
		"Ú": "U", "Ù": "U", "Û": "U", "Ü": "U",
		"Ç": "C",
		"Ñ": "N",
	}

	for accented, plain := range replacements {
		name = strings.ReplaceAll(name, accented, plain)
	}

	// Remove any character that is not A-Z, 0-9, or space
	re := regexp.MustCompile(`[^A-Z0-9 ]`)
	name = re.ReplaceAllString(name, "")

	// Clean up multiple spaces
	re = regexp.MustCompile(`\s+`)
	name = re.ReplaceAllString(name, " ")

	return strings.TrimSpace(name)
}

// ValidateFieldLength validates that a field doesn't exceed the maximum length
func ValidateFieldLength(field, value string, maxLength int) error {
	if len(value) > maxLength {
		return NewValidationError(field + " exceeds maximum length of " + strconv.Itoa(maxLength) + " characters")
	}
	return nil
}
