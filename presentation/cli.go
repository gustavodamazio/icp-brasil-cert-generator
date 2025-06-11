package presentation

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourorg/icp-brasil-cert-generator/application"
	"github.com/yourorg/icp-brasil-cert-generator/infrastructure"
)

// CLI represents the command line interface
type CLI struct {
	generator *application.CertificateGeneratorService
}

// NewCLI creates a new CLI instance
func NewCLI() *CLI {
	repository := infrastructure.NewFileRepository()
	generator := application.NewCertificateGeneratorService(repository)

	return &CLI{
		generator: generator,
	}
}

// Execute executes the CLI
func (c *CLI) Execute() error {
	rootCmd := c.createRootCommand()
	return rootCmd.Execute()
}

// createRootCommand creates the root command
func (c *CLI) createRootCommand() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "icp-brasil-cert-generator",
		Short: "Generate ICP Brasil mock certificates",
		Long: `A command line tool to generate ICP Brasil mock certificates
following the official standards and specifications.

Supports generation of single or multiple certificates in PEM, PFX, CERT, and CRT formats
with proper ICP Brasil extensions and structure.`,
	}

	// Add subcommands
	rootCmd.AddCommand(c.createGenerateCommand())
	rootCmd.AddCommand(c.createConfigCommand())
	rootCmd.AddCommand(c.createValidateCommand())

	return rootCmd
}

// createGenerateCommand creates the generate command
func (c *CLI) createGenerateCommand() *cobra.Command {
	var (
		configFile  string
		certType    string
		personType  string
		name        string
		document    string
		email       string
		validFrom   string
		validUntil  string
		keySize     int
		outputDir   string
		pfxPassword string
		orgUnit     string
		dnsNames    []string
		formats     []string
	)

	var generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate ICP Brasil certificates",
		Long: `Generate ICP Brasil certificates with the specified parameters.
You can either use a configuration file (supports multiple certificates) or provide parameters via command line flags (single certificate).

Date format: dd/MM/yyyy HH:mm:ss or dd/MM/yyyy

Supported output formats:
  - pem:  PEM format (certificate.crt + certificate.key)
  - pfx:  PKCS#12 format (certificate.pfx)
  - cert: DER format with .cert extension (certificate.cert)
  - crt:  DER format with .crt extension (certificate.crt)

Note: .cert and .crt formats contain only the certificate in DER encoding,
following ICP Brasil standards. They do not include the private key.

Examples:
  # Generate multiple certificates using config file
  icp-brasil-cert-generator generate --config config-multiple.json

  # Generate single certificate using command line flags
  icp-brasil-cert-generator generate \
    --type A3 \
    --person-type individual \
    --name "JOAO DA SILVA" \
    --document "12345678901" \
    --valid-from "01/01/2024 00:00:00" \
    --valid-until "01/01/2027 23:59:59" \
    --output ./certificates \
    --pfx-password "mypassword" \
    --formats pem,pfx,cert,crt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runGenerate(configFile, certType, personType, name, document, email,
				validFrom, validUntil, keySize, outputDir, pfxPassword, orgUnit, dnsNames, formats)
		},
	}

	// Add flags
	generateCmd.Flags().StringVarP(&configFile, "config", "c", "", "Configuration file path (supports multiple certificates)")
	generateCmd.Flags().StringVarP(&certType, "type", "t", "A3", "Certificate type (A3, A4, SE-S, SE-H, AE-S, AE-H)")
	generateCmd.Flags().StringVarP(&personType, "person-type", "p", "individual", "Person type (individual, legal_entity)")
	generateCmd.Flags().StringVarP(&name, "name", "n", "", "Certificate holder name")
	generateCmd.Flags().StringVarP(&document, "document", "d", "", "CPF (for individuals) or CNPJ (for legal entities)")
	generateCmd.Flags().StringVarP(&email, "email", "e", "", "Email address")
	generateCmd.Flags().StringVar(&validFrom, "valid-from", "", "Valid from date (dd/MM/yyyy HH:mm:ss)")
	generateCmd.Flags().StringVar(&validUntil, "valid-until", "", "Valid until date (dd/MM/yyyy HH:mm:ss)")
	generateCmd.Flags().IntVar(&keySize, "key-size", 2048, "RSA key size in bits")
	generateCmd.Flags().StringVarP(&outputDir, "output", "o", "./output", "Output directory")
	generateCmd.Flags().StringVar(&pfxPassword, "pfx-password", "changeme", "Password for PFX file")
	generateCmd.Flags().StringVar(&orgUnit, "org-unit", "Mock Certificate", "Organizational unit")
	generateCmd.Flags().StringSliceVar(&dnsNames, "dns-names", []string{}, "DNS names for Subject Alternative Name")
	generateCmd.Flags().StringSliceVarP(&formats, "formats", "f", []string{"pem", "pfx"}, "Output formats (pem, pfx, cert, crt)")

	return generateCmd
}

// createConfigCommand creates the config command
func (c *CLI) createConfigCommand() *cobra.Command {
	var configCmd = &cobra.Command{
		Use:   "config",
		Short: "Configuration management commands",
	}

	// Add subcommands
	configCmd.AddCommand(c.createConfigInitCommand())
	configCmd.AddCommand(c.createConfigValidateCommand())

	return configCmd
}

// createConfigInitCommand creates the config init command
func (c *CLI) createConfigInitCommand() *cobra.Command {
	var outputPath string

	var initCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize a default configuration file",
		Long: `Create a default configuration file with multiple certificate examples
that can be customized and used with the generate command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runConfigInit(outputPath)
		},
	}

	initCmd.Flags().StringVarP(&outputPath, "output", "o", "config.json", "Output configuration file path")

	return initCmd
}

// createConfigValidateCommand creates the config validate command
func (c *CLI) createConfigValidateCommand() *cobra.Command {
	var configPath string

	var validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "Validate a configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runConfigValidate(configPath)
		},
	}

	validateCmd.Flags().StringVarP(&configPath, "config", "c", "config.json", "Configuration file path")

	return validateCmd
}

// createValidateCommand creates the validate command
func (c *CLI) createValidateCommand() *cobra.Command {
	var (
		certPath string
		pfxPath  string
		password string
	)

	var validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "Validate generated certificates",
		Long: `Validate the structure and content of generated certificates
to ensure they conform to ICP Brasil standards.

Supports validation of PEM (.crt), DER (.cert, .crt), and PFX (.pfx) formats.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runValidate(certPath, pfxPath, password)
		},
	}

	validateCmd.Flags().StringVar(&certPath, "cert", "", "Certificate file path (PEM, DER, .cert, or .crt format)")
	validateCmd.Flags().StringVar(&pfxPath, "pfx", "", "PFX file path")
	validateCmd.Flags().StringVar(&password, "password", "", "PFX password")

	return validateCmd
}

// runGenerate executes the generate command
func (c *CLI) runGenerate(configFile, certType, personType, name, document, email,
	validFrom, validUntil string, keySize int, outputDir, pfxPassword, orgUnit string, dnsNames, formats []string) error {

	var config *application.Config
	var err error

	// Load configuration
	if configFile != "" {
		config, err = application.LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Generate multiple certificates
		return c.runGenerateMultiple(config)
	} else {
		// Create config from command line arguments (single certificate)
		config = c.createConfigFromFlags(certType, personType, name, document, email,
			validFrom, validUntil, keySize, outputDir, pfxPassword, orgUnit, dnsNames, formats)

		// Generate single certificate
		return c.runGenerateSingle(config)
	}
}

// runGenerateMultiple generates multiple certificates from config file
func (c *CLI) runGenerateMultiple(config *application.Config) error {
	// Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	fmt.Printf("Generating %d ICP Brasil certificates...\n", config.GetCertificateCount())

	// Generate certificates
	certificates, err := c.generator.GenerateMultiple(config)
	if err != nil {
		return fmt.Errorf("failed to generate certificates: %w", err)
	}

	// Save certificates
	fmt.Println("Saving certificates...")
	if err := c.generator.SaveMultipleCertificates(certificates, config); err != nil {
		return fmt.Errorf("failed to save certificates: %w", err)
	}

	// Print success message
	fmt.Printf("✅ %d certificates generated successfully!\n", len(certificates))
	fmt.Printf("📁 Base output directory: %s\n", config.Output.Directory)
	fmt.Printf("🔧 Output formats: %s\n", config.GetFormatsString())
	fmt.Printf("\nGenerated certificates:\n")

	for i, cert := range certificates {
		certConfig := config.Certificates[i]
		fmt.Printf("  📄 %s (%s)\n", certConfig.Name, cert.Type)
		fmt.Printf("     👤 Subject: %s\n", cert.SubjectDN.CommonName)
		fmt.Printf("     🆔 Document: %s\n", cert.SubjectDN.SerialNumber)
		fmt.Printf("     📅 Valid: %s to %s\n",
			cert.ValidityPeriod.NotBefore.Format("02/01/2006"),
			cert.ValidityPeriod.NotAfter.Format("02/01/2006"))
		fmt.Printf("     📁 Directory: %s\n", config.GetCertificateOutputPath(certConfig.Name))
		fmt.Println()
	}

	return nil
}

// runGenerateSingle generates a single certificate from command line flags
func (c *CLI) runGenerateSingle(config *application.Config) error {
	// Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Convert to domain config (single certificate)
	domainConfigs, err := config.ToCertificateConfigs()
	if err != nil {
		return fmt.Errorf("failed to convert config: %w", err)
	}

	domainConfig := domainConfigs[0]

	// Create output directory
	if err := os.MkdirAll(config.Output.Directory, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate certificate
	fmt.Println("Generating ICP Brasil certificate...")
	cert, err := c.generator.Generate(domainConfig)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Save certificates in specified formats
	fmt.Println("Saving certificates...")
	if err := c.generator.SaveCertificatesWithFormats(cert, config.Output.Directory, config.Security.PFXPassword, config.Output.Formats); err != nil {
		return fmt.Errorf("failed to save certificates: %w", err)
	}

	// Print success message
	fmt.Printf("✅ Certificate generated successfully!\n")
	fmt.Printf("📁 Output directory: %s\n", config.Output.Directory)
	fmt.Printf("📄 Certificate type: %s\n", cert.Type)
	fmt.Printf("👤 Subject: %s\n", cert.SubjectDN.CommonName)
	fmt.Printf("🆔 Document: %s\n", cert.SubjectDN.SerialNumber)
	fmt.Printf("📅 Valid from: %s\n", cert.ValidityPeriod.NotBefore.Format("02/01/2006 15:04:05"))
	fmt.Printf("📅 Valid until: %s\n", cert.ValidityPeriod.NotAfter.Format("02/01/2006 15:04:05"))
	fmt.Printf("🔧 Output formats: %s\n", config.GetFormatsString())
	fmt.Printf("\nFiles generated:\n")

	for _, format := range config.Output.Formats {
		switch strings.ToLower(format) {
		case "pem":
			fmt.Printf("  - certificate.crt (PEM certificate)\n")
			fmt.Printf("  - certificate.key (PEM private key)\n")
		case "pfx":
			fmt.Printf("  - certificate.pfx (PKCS#12 with password: %s)\n", config.Security.PFXPassword)
		case "cert":
			fmt.Printf("  - certificate.cert (DER certificate)\n")
		case "crt":
			fmt.Printf("  - certificate.crt (DER certificate)\n")
		}
	}

	return nil
}

// runConfigInit executes the config init command
func (c *CLI) runConfigInit(outputPath string) error {
	config := application.CreateDefaultConfig()

	if err := application.SaveConfig(config, outputPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("✅ Default configuration created: %s\n", outputPath)
	fmt.Printf("📝 Configuration includes %d example certificates\n", config.GetCertificateCount())
	fmt.Println("📝 Edit the configuration file and run 'generate --config " + outputPath + "'")
	fmt.Printf("🔧 Default formats: %s\n", strings.Join(config.Output.Formats, ", "))

	return nil
}

// runConfigValidate executes the config validate command
func (c *CLI) runConfigValidate(configPath string) error {
	config, err := application.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	fmt.Printf("✅ Configuration is valid: %s\n", configPath)
	fmt.Printf("📄 Contains %d certificate(s)\n", config.GetCertificateCount())
	fmt.Printf("🔧 Output formats: %s\n", config.GetFormatsString())

	fmt.Println("\nCertificates in configuration:")
	for i, cert := range config.Certificates {
		fmt.Printf("  %d. %s (%s, %s)\n", i+1, cert.Name, cert.Type, cert.PersonType)
	}

	return nil
}

// runValidate executes the validate command
func (c *CLI) runValidate(certPath, pfxPath, password string) error {
	if certPath == "" && pfxPath == "" {
		return fmt.Errorf("either --cert or --pfx must be specified")
	}

	if pfxPath != "" && password == "" {
		return fmt.Errorf("--password is required when validating PFX files")
	}

	repository := infrastructure.NewFileRepository()

	if certPath != "" {
		var cert *x509.Certificate
		var err error

		// Determine file format based on extension or content
		if strings.HasSuffix(strings.ToLower(certPath), ".cert") || strings.HasSuffix(strings.ToLower(certPath), ".crt") {
			// Try DER format first
			cert, err = repository.LoadCertificateDER(certPath)
			if err != nil {
				// Fallback to PEM format
				cert, err = repository.LoadCertificatePEM(certPath)
			}
		} else {
			// Try PEM format first
			cert, err = repository.LoadCertificatePEM(certPath)
			if err != nil {
				// Fallback to DER format
				cert, err = repository.LoadCertificateDER(certPath)
			}
		}

		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}

		fmt.Printf("✅ Certificate loaded successfully\n")
		fmt.Printf("📄 Subject: %s\n", cert.Subject.String())
		fmt.Printf("📅 Valid from: %s\n", cert.NotBefore.Format("02/01/2006 15:04:05"))
		fmt.Printf("📅 Valid until: %s\n", cert.NotAfter.Format("02/01/2006 15:04:05"))
		fmt.Printf("🔑 Public key algorithm: %s\n", cert.PublicKeyAlgorithm.String())
		fmt.Printf("📝 Signature algorithm: %s\n", cert.SignatureAlgorithm.String())
	}

	if pfxPath != "" {
		cert, err := repository.LoadPFX(pfxPath, password)
		if err != nil {
			return fmt.Errorf("failed to load PFX: %w", err)
		}
		fmt.Printf("✅ PFX loaded successfully\n")
		fmt.Printf("📄 Subject: %s\n", cert.X509Cert.Subject.String())
		fmt.Printf("📅 Valid from: %s\n", cert.X509Cert.NotBefore.Format("02/01/2006 15:04:05"))
		fmt.Printf("📅 Valid until: %s\n", cert.X509Cert.NotAfter.Format("02/01/2006 15:04:05"))
	}

	return nil
}

// createConfigFromFlags creates a configuration from command line flags
func (c *CLI) createConfigFromFlags(certType, personType, name, document, email,
	validFrom, validUntil string, keySize int, outputDir, pfxPassword, orgUnit string, dnsNames, formats []string) *application.Config {

	// Set defaults for empty values
	if validFrom == "" {
		validFrom = time.Now().Format("02/01/2006 15:04:05")
	}
	if validUntil == "" {
		validUntil = time.Now().AddDate(3, 0, 0).Format("02/01/2006 15:04:05")
	}

	// Use provided formats or default
	if len(formats) == 0 {
		formats = []string{"pem", "pfx"}
	}

	return &application.Config{
		Certificates: []application.CertificateSettings{
			{
				Name:         "single_cert",
				Type:         certType,
				PersonType:   personType,
				SubjectName:  name,
				Document:     document,
				Email:        email,
				ValidFrom:    validFrom,
				ValidUntil:   validUntil,
				KeySize:      keySize,
				Organization: "ICP-Brasil",
				OrgUnit:      orgUnit,
				Country:      "BR",
				DNSNames:     dnsNames,
			},
		},
		Output: application.OutputSettings{
			Directory: outputDir,
			Formats:   formats,
		},
		Security: application.SecuritySettings{
			PFXPassword: pfxPassword,
		},
	}
}
