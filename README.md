# ICP Brasil Certificate Generator

A comprehensive command-line tool for generating mock ICP Brasil certificates following official standards and specifications. This tool supports generating single or multiple certificates in various formats (PEM, PFX, CERT, CRT) with proper ICP Brasil extensions and structure.

## Features

- **Multiple Certificate Generation**: Generate multiple certificates from a single configuration file
- **Multiple Output Formats**: Support for PEM, PFX, CERT, and CRT formats
- **ICP Brasil Compliance**: Follows official ICP Brasil standards and specifications
- **Certificate Types**: Support for A3, A4, SE-S, SE-H, AE-S, and AE-H certificate types
- **Person Types**: Support for both individual and legal entity certificates
- **Comprehensive Makefile**: Easy-to-use build, test, and example generation targets
- **Validation Tools**: Built-in certificate validation functionality
- **Flexible Configuration**: JSON-based configuration with extensive customization options

## Quick Start

### Prerequisites

- Go 1.24 or later
- Make (for using the Makefile)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd icp-brasil-cert-generator
```

2. Install dependencies and build:
```bash
make install
make build
```

### Generate Your First Certificates

1. Create a default configuration file:
```bash
make config init
```

2. Generate certificates using the configuration:
```bash
./build/icp-brasil-cert-generator generate --config config.json
```

Or use the Makefile for quick examples:
```bash
make examples-mixed
```

## Configuration

### Multiple Certificate Configuration

The application now supports generating multiple certificates from a single JSON configuration file. Here's the structure:

```json
{
  "certificates": [
    {
      "name": "individual_cert",
      "type": "A3",
      "person_type": "individual",
      "subject_name": "JOAO DA SILVA",
      "document": "12345678901",
      "email": "joao.silva@example.com",
      "valid_from": "01/01/2024 00:00:00",
      "valid_until": "01/01/2027 23:59:59",
      "key_size": 2048,
      "organization": "ICP-Brasil",
      "org_unit": "Mock Certificate",
      "country": "BR",
      "dns_names": []
    },
    {
      "name": "company_cert",
      "type": "A3",
      "person_type": "legal_entity",
      "subject_name": "EMPRESA EXEMPLO LTDA",
      "document": "12345678000195",
      "email": "contato@empresa.com.br",
      "valid_from": "01/01/2024 00:00:00",
      "valid_until": "01/01/2027 23:59:59",
      "key_size": 2048,
      "organization": "ICP-Brasil",
      "org_unit": "Mock Certificate",
      "country": "BR",
      "dns_names": ["empresa.com.br", "www.empresa.com.br"]
    }
  ],
  "output": {
    "directory": "./.outputs",
    "formats": ["pem", "pfx", "cert", "crt"]
  },
  "security": {
    "pfx_password": "changeme"
  }
}
```

### Certificate Configuration Fields

#### Required Fields
- `name`: Unique identifier for the certificate (used for output directory naming)
- `type`: Certificate type (A3, A4, SE-S, SE-H, AE-S, AE-H)
- `person_type`: Type of certificate holder (individual, legal_entity)
- `subject_name`: Name of the certificate holder
- `document`: CPF (for individuals) or CNPJ (for legal entities)
- `valid_from`: Certificate validity start date
- `valid_until`: Certificate validity end date

#### Optional Fields
- `email`: Email address for the certificate
- `key_size`: RSA key size in bits (default: 2048)
- `organization`: Organization name (default: "ICP-Brasil")
- `org_unit`: Organizational unit (default: "Mock Certificate")
- `country`: Country code (default: "BR")
- `dns_names`: Array of DNS names for Subject Alternative Name

### Output Configuration

- `directory`: Base output directory for all certificates
- `formats`: Array of output formats (pem, pfx, cert, crt)

### Security Configuration

- `pfx_password`: Password for PFX files

## Certificate Types

| Type | Description | Use Case |
|------|-------------|----------|
| A3 | Digital certificate for authentication and digital signature | General purpose authentication |
| A4 | Digital certificate with higher security level | High-security authentication |
| SE-S | Digital signature certificate (software) | Document signing |
| SE-H | Digital signature certificate (hardware) | Hardware-based document signing |
| AE-S | Application certificate (software) | Application authentication |
| AE-H | Application certificate (hardware) | Hardware-based application authentication |

## Output Formats

| Format | Description | Files Generated |
|--------|-------------|-----------------|
| PEM | Privacy-Enhanced Mail format | certificate.crt, certificate.key |
| PFX | PKCS#12 format (password protected) | certificate.pfx |
| CERT | DER format with .cert extension | certificate.cert |
| CRT | DER format with .crt extension | certificate.crt |

## Makefile Usage

The project includes a comprehensive Makefile with the following targets:

### Build Targets
```bash
make build              # Build the application binary
make clean              # Clean build artifacts and output directories
make install            # Install Go dependencies
```

### Development Targets
```bash
make fmt                # Format Go source code
make vet                # Run go vet on source code
make deps-check         # Check for outdated dependencies
make deps-update        # Update Go dependencies
make run-dev            # Run the application in development mode
```

### Testing Targets
```bash
make test               # Run all tests
make test-verbose       # Run tests with verbose output
make test-coverage      # Run tests with coverage report
```

### Certificate Generation Targets
```bash
make examples           # Generate all example certificates
make examples-individual # Generate individual certificates
make examples-company   # Generate company certificates
make examples-mixed     # Generate mixed certificates (individuals + companies)
make examples-all-formats # Generate certificates in all formats
```

### Validation Targets
```bash
make validate-examples  # Validate generated example certificates
```

### Help
```bash
make help              # Show all available targets with descriptions
```

## Command Line Usage

### Generate Multiple Certificates
```bash
# Using configuration file (recommended for multiple certificates)
./build/icp-brasil-cert-generator generate --config examples/config-mixed.json
```

### Generate Single Certificate
```bash
# Using command line flags (single certificate)
./build/icp-brasil-cert-generator generate \
  --type A3 \
  --person-type individual \
  --name "JOAO DA SILVA" \
  --document "12345678901" \
  --valid-from "01/01/2024 00:00:00" \
  --valid-until "01/01/2027 23:59:59" \
  --output ./.outputs \
  --pfx-password "mypassword" \
  --formats pem,pfx,cert,crt
```

### Configuration Management
```bash
# Create default configuration
./build/icp-brasil-cert-generator config init --output config.json

# Validate configuration
./build/icp-brasil-cert-generator config validate --config config.json
```

### Certificate Validation
```bash
# Validate PEM certificate
./build/icp-brasil-cert-generator validate --cert certificate.crt

# Validate PFX certificate
./build/icp-brasil-cert-generator validate --pfx certificate.pfx --password mypassword
```

## Example Configurations

The `examples/` directory contains several pre-configured examples:

- `config.json` - Single individual certificate
- `config-legal-entity.json` - Single company certificate
- `config-multiple.json` - Multiple certificates (individual + company)
- `config-individuals.json` - Multiple individual certificates
- `config-companies.json` - Multiple company certificates
- `config-mixed.json` - Mixed certificate types and person types
- `config-all-formats.json` - Certificate with all output formats

## Output Structure

When generating multiple certificates, each certificate gets its own subdirectory:

```
.outputs/
├── individuals/
│   └── individual_cert/
│       ├── certificate.crt
│       ├── certificate.key
│       ├── certificate.pfx
│       └── certificate.cert
├── companies/
│   └── company_cert/
│       ├── certificate.crt
│       ├── certificate.key
│       ├── certificate.pfx
│       └── certificate.cert
├── mixed/
│   ├── individual_cert/
│   └── company_cert/
└── all-formats/
    └── certificates...
```

## Development

### Project Structure
```
├── application/        # Application layer (use cases, services)
├── cmd/               # Command line interface entry point
├── domain/            # Domain layer (entities, value objects)
├── examples/          # Example configuration files
├── infrastructure/    # Infrastructure layer (repositories, external services)
├── presentation/      # Presentation layer (CLI, handlers)
├── tests/            # Test files
├── Makefile          # Build and development automation
└── README.md         # This file
```

### Running Tests
```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run tests with verbose output
make test-verbose
```

### Code Quality
```bash
# Format code
make fmt

# Run static analysis
make vet

# Complete development workflow
make dev-test
```

## Security Considerations

⚠️ **Important**: This tool generates **mock certificates** for testing and development purposes only. These certificates should **never** be used in production environments or for actual digital signatures.

- Generated certificates are self-signed and not issued by a real Certificate Authority
- Private keys are generated locally and should be handled securely
- PFX files are password-protected as specified in the configuration
- The tool follows ICP Brasil standards for educational and testing purposes

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure you have write permissions to the output directory
2. **Invalid Date Format**: Use the format `dd/MM/yyyy HH:mm:ss` or `dd/MM/yyyy`
3. **Invalid Document**: Ensure CPF/CNPJ numbers are valid according to Brazilian standards
4. **Duplicate Certificate Names**: Each certificate in the configuration must have a unique name

### Getting Help

```bash
# Show general help
./build/icp-brasil-cert-generator --help

# Show help for specific commands
./build/icp-brasil-cert-generator generate --help
./build/icp-brasil-cert-generator config --help
./build/icp-brasil-cert-generator validate --help

# Show Makefile targets
make help
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `make test`
5. Format code: `make fmt`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- ICP Brasil for the certificate standards and specifications
- Go community for excellent cryptographic libraries
- Contributors and testers who helped improve this tool
