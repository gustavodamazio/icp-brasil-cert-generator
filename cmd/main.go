package main

import (
	"fmt"
	"os"

	"github.com/yourorg/icp-brasil-cert-generator/presentation"
)

func main() {
	cli := presentation.NewCLI()

	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
