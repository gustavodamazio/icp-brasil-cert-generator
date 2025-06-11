package domain

import "fmt"

// DomainError represents a domain-specific error
type DomainError struct {
	Type    string
	Message string
	Cause   error
}

func (e DomainError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e DomainError) Unwrap() error {
	return e.Cause
}

// ValidationError represents a validation error
type ValidationError struct {
	DomainError
}

func NewValidationError(message string) ValidationError {
	return ValidationError{
		DomainError: DomainError{
			Type:    "ValidationError",
			Message: message,
		},
	}
}

func NewValidationErrorWithCause(message string, cause error) ValidationError {
	return ValidationError{
		DomainError: DomainError{
			Type:    "ValidationError",
			Message: message,
			Cause:   cause,
		},
	}
}

// GenerationError represents a certificate generation error
type GenerationError struct {
	DomainError
}

func NewGenerationError(message string) GenerationError {
	return GenerationError{
		DomainError: DomainError{
			Type:    "GenerationError",
			Message: message,
		},
	}
}

func NewGenerationErrorWithCause(message string, cause error) GenerationError {
	return GenerationError{
		DomainError: DomainError{
			Type:    "GenerationError",
			Message: message,
			Cause:   cause,
		},
	}
}

// PersistenceError represents a persistence error
type PersistenceError struct {
	DomainError
}

func NewPersistenceError(message string) PersistenceError {
	return PersistenceError{
		DomainError: DomainError{
			Type:    "PersistenceError",
			Message: message,
		},
	}
}

func NewPersistenceErrorWithCause(message string, cause error) PersistenceError {
	return PersistenceError{
		DomainError: DomainError{
			Type:    "PersistenceError",
			Message: message,
			Cause:   cause,
		},
	}
}
