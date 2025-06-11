# ICP Brasil Certificate Generator Makefile
# This Makefile provides convenient targets for building, testing, and generating example certificates

# Variables
BINARY_NAME=icp-brasil-cert-generator
GO_FILES=$(shell find . -name "*.go" -type f)
EXAMPLES_DIR=examples
OUTPUT_DIR=.outputs
BUILD_DIR=build

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOVET=$(GOCMD) vet
GOFMT=gofmt

# Build flags
LDFLAGS=-ldflags "-s -w"
BUILD_FLAGS=-trimpath $(LDFLAGS)

# Default target
.DEFAULT_GOAL := help

# Phony targets (targets that don't create files)
.PHONY: help build test test-verbose test-coverage clean install examples examples-individual examples-company examples-mixed examples-all-formats validate-examples fmt vet deps-check deps-update run-dev

## help: Show this help message
help:
	@echo "ICP Brasil Certificate Generator - Available Make targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  build              Build the application binary"
	@echo "  clean              Clean build artifacts and output directories"
	@echo "  install            Install Go dependencies"
	@echo ""
	@echo "Development targets:"
	@echo "  fmt                Format Go source code"
	@echo "  vet                Run go vet on source code"
	@echo "  deps-check         Check for outdated dependencies"
	@echo "  deps-update        Update Go dependencies"
	@echo "  run-dev            Run the application in development mode"
	@echo ""
	@echo "Testing targets:"
	@echo "  test               Run all tests"
	@echo "  test-verbose       Run tests with verbose output"
	@echo "  test-coverage      Run tests with coverage report"
	@echo ""
	@echo "Certificate generation targets:"
	@echo "  examples           Generate all example certificates"
	@echo "  examples-individual Generate individual certificates"
	@echo "  examples-company   Generate company certificates"
	@echo "  examples-mixed     Generate mixed certificates (individuals + companies)"
	@echo "  examples-all-formats Generate certificates in all formats"
	@echo ""
	@echo "Validation targets:"
	@echo "  validate-examples  Validate generated example certificates"
	@echo ""
	@echo "Usage examples:"
	@echo "  make build                    # Build the application"
	@echo "  make test                     # Run tests"
	@echo "  make examples                 # Generate all examples"
	@echo "  make examples-individual      # Generate only individual certificates"
	@echo "  make clean                    # Clean up generated files"

## Run: Run the application locally not compiled with arguments
run:
	@echo "Running the application locally..."
	$(GOCMD) run ./cmd/main.go $(ARGS)
	@echo "✅ Application running"

## build: Build the application binary
build: deps-check
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/main.go
	@echo "✅ Build completed: $(BUILD_DIR)/$(BINARY_NAME)"

## test: Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...
	@echo "✅ Tests completed"

## test-verbose: Run tests with verbose output
test-verbose:
	@echo "Running tests with verbose output..."
	$(GOTEST) -v -race ./...
	@echo "✅ Verbose tests completed"

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) -v -race -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "✅ Coverage report generated: $(BUILD_DIR)/coverage.html"
	@echo "📊 Coverage summary:"
	$(GOCMD) tool cover -func=$(BUILD_DIR)/coverage.out | tail -1

## clean: Clean build artifacts and output directories
clean:
	@echo "Cleaning build artifacts and output directories..."
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -rf $(OUTPUT_DIR)
	@echo "✅ Clean completed"

## install: Install Go dependencies
install:
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✅ Dependencies installed"

## fmt: Format Go source code
fmt:
	@echo "Formatting Go source code..."
	$(GOFMT) -s -w $(GO_FILES)
	@echo "✅ Code formatted"

## vet: Run go vet on source code
vet:
	@echo "Running go vet..."
	$(GOVET) ./...
	@echo "✅ Vet completed"

## deps-check: Check for outdated dependencies
deps-check:
	@echo "Checking dependencies..."
	$(GOMOD) verify
	@echo "✅ Dependencies verified"

## deps-update: Update Go dependencies
deps-update:
	@echo "Updating dependencies..."
	$(GOMOD) get -u ./...
	$(GOMOD) tidy
	@echo "✅ Dependencies updated"

## run-dev: Run the application in development mode
run-dev: build
	@echo "Running application in development mode..."
	./$(BUILD_DIR)/$(BINARY_NAME) --help

## examples: Generate all example certificates
examples: build examples-individual examples-company examples-mixed examples-all-formats
	@echo "✅ All example certificates generated"

## examples-individual: Generate individual certificates
examples-individual: build
	@echo "Generating individual certificates..."
	@mkdir -p $(OUTPUT_DIR)/individuals
	./$(BUILD_DIR)/$(BINARY_NAME) generate --config $(EXAMPLES_DIR)/config-individuals.json --output $(OUTPUT_DIR)/individuals
	@echo "✅ Individual certificates generated in $(OUTPUT_DIR)/individuals/"

## examples-company: Generate company certificates
examples-company: build
	@echo "Generating company certificates..."
	@mkdir -p $(OUTPUT_DIR)/companies
	./$(BUILD_DIR)/$(BINARY_NAME) generate --config $(EXAMPLES_DIR)/config-companies.json --output $(OUTPUT_DIR)/companies
	@echo "✅ Company certificates generated in $(OUTPUT_DIR)/companies/"

## examples-mixed: Generate mixed certificates (individuals + companies)
examples-mixed: build
	@echo "Generating mixed certificates..."
	@mkdir -p $(OUTPUT_DIR)/mixed
	./$(BUILD_DIR)/$(BINARY_NAME) generate --config $(EXAMPLES_DIR)/config-mixed.json --output $(OUTPUT_DIR)/mixed
	@echo "✅ Mixed certificates generated in $(OUTPUT_DIR)/mixed/"

## examples-all-formats: Generate certificates in all formats
examples-all-formats: build
	@echo "Generating certificates in all formats..."
	@mkdir -p $(OUTPUT_DIR)/all-formats
	./$(BUILD_DIR)/$(BINARY_NAME) generate --config $(EXAMPLES_DIR)/config-all-formats.json --output $(OUTPUT_DIR)/all-formats
	@echo "✅ All format certificates generated in $(OUTPUT_DIR)/all-formats/"

## validate-examples: Validate generated example certificates
validate-examples:
	@echo "Validating generated example certificates..."
	@if [ ! -f $(BUILD_DIR)/$(BINARY_NAME) ]; then \
		echo "❌ Binary not found. Run 'make build' first."; \
		exit 1; \
	fi
	@echo "Validating individual certificates..."
	@if [ -d "$(OUTPUT_DIR)/individuals" ]; then \
		for cert_dir in $(OUTPUT_DIR)/individuals/*/; do \
			if [ -f "$$cert_dir/certificate.crt" ]; then \
				echo "  Validating $$cert_dir/certificate.crt"; \
				./$(BUILD_DIR)/$(BINARY_NAME) validate --cert "$$cert_dir/certificate.crt" || true; \
			fi; \
			if [ -f "$$cert_dir/certificate.pfx" ]; then \
				echo "  Validating $$cert_dir/certificate.pfx"; \
				./$(BUILD_DIR)/$(BINARY_NAME) validate --pfx "$$cert_dir/certificate.pfx" --password "individuals123" || true; \
			fi; \
		done; \
	else \
		echo "  No individual certificates found. Run 'make examples-individual' first."; \
	fi
	@echo "Validating company certificates..."
	@if [ -d "$(OUTPUT_DIR)/companies" ]; then \
		for cert_dir in $(OUTPUT_DIR)/companies/*/; do \
			if [ -f "$$cert_dir/certificate.crt" ]; then \
				echo "  Validating $$cert_dir/certificate.crt"; \
				./$(BUILD_DIR)/$(BINARY_NAME) validate --cert "$$cert_dir/certificate.crt" || true; \
			fi; \
			if [ -f "$$cert_dir/certificate.pfx" ]; then \
				echo "  Validating $$cert_dir/certificate.pfx"; \
				./$(BUILD_DIR)/$(BINARY_NAME) validate --pfx "$$cert_dir/certificate.pfx" --password "companies456" || true; \
			fi; \
		done; \
	else \
		echo "  No company certificates found. Run 'make examples-company' first."; \
	fi
	@echo "Validating mixed certificates..."
	@if [ -d "$(OUTPUT_DIR)/mixed" ]; then \
		for cert_dir in $(OUTPUT_DIR)/mixed/*/; do \
			if [ -f "$$cert_dir/certificate.crt" ]; then \
				echo "  Validating $$cert_dir/certificate.crt"; \
				./$(BUILD_DIR)/$(BINARY_NAME) validate --cert "$$cert_dir/certificate.crt" || true; \
			fi; \
			if [ -f "$$cert_dir/certificate.pfx" ]; then \
				echo "  Validating $$cert_dir/certificate.pfx"; \
				./$(BUILD_DIR)/$(BINARY_NAME) validate --pfx "$$cert_dir/certificate.pfx" --password "mixed789" || true; \
			fi; \
		done; \
	else \
		echo "  No mixed certificates found. Run 'make examples-mixed' first."; \
	fi
	@echo "Validating all-formats certificates..."
	@if [ -d "$(OUTPUT_DIR)/all-formats" ]; then \
		for cert_dir in $(OUTPUT_DIR)/all-formats/*/; do \
			if [ -f "$$cert_dir/certificate.crt" ]; then \
				echo "  Validating $$cert_dir/certificate.crt"; \
				./$(BUILD_DIR)/$(BINARY_NAME) validate --cert "$$cert_dir/certificate.crt" || true; \
			fi; \
			if [ -f "$$cert_dir/certificate.pfx" ]; then \
				echo "  Validating $$cert_dir/certificate.pfx"; \
				./$(BUILD_DIR)/$(BINARY_NAME) validate --pfx "$$cert_dir/certificate.pfx" --password "allformats" || true; \
			fi; \
		done; \
	else \
		echo "  No all-formats certificates found. Run 'make examples-all-formats' first."; \
	fi
	@echo "✅ Certificate validation completed"

# Quick development workflow targets
dev-setup: install build test
	@echo "✅ Development environment setup completed"

dev-test: fmt vet test
	@echo "✅ Development testing completed"

# CI/CD targets
ci: deps-check fmt vet test-coverage build
	@echo "✅ CI pipeline completed"

# Show file structure
show-structure:
	@echo "Project structure:"
	@find . -type f -name "*.go" -o -name "*.json" -o -name "Makefile" | grep -E '\.(go|json)$$|Makefile$$' | sort

# Generate a single certificate quickly (for testing)
quick-cert: build
	@echo "Generating a quick test certificate..."
	./$(BUILD_DIR)/$(BINARY_NAME) generate \
		--type A3 \
		--person-type individual \
		--name "TESTE RAPIDO" \
		--document "12345678901" \
		--output ./quick-test \
		--formats pem,pfx
	@echo "✅ Quick certificate generated in ./quick-test/"
