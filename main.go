package main

import (
	"fmt"
	"log/slog"
	"os"

	grype_helper "github.com/flavio/sbom-merger/internal/grype"
	trivy_helper "github.com/flavio/sbom-merger/internal/trivy"
	"github.com/flavio/sbom-merger/internal/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <image>\n", os.Args[0])
		os.Exit(1)
	}
	image := os.Args[1]

	trivySBOM, err := generateSBOM(types.TRIVY, image)
	if err != nil {
		slog.Error("failed to generate trivy sbom", "error", err)
		os.Exit(1)
	}

	trivyReportBytes, err := generateReport(types.TRIVY, trivySBOM)
	if err != nil {
		slog.Error("failed to generate trivy report", "error", err)
		os.Exit(1)
	}

	trivyReport, err := trivy_helper.ConvertReport(trivyReportBytes)
	if err != nil {
		slog.Error("failed to convert trivy report", "error", err)
		os.Exit(1)
	}

	syftSBOMBytes, err := generateSBOM(types.GRYPE, image)
	if err != nil {
		slog.Error("failed to generate syft sbom", "error", err)
		os.Exit(1)
	}
	grypeReportBytes, err := generateReport(types.GRYPE, syftSBOMBytes)
	if err != nil {
		slog.Error("failed to generate grype report", "error", err)
		os.Exit(1)
	}

	grypeReport, err := grype_helper.ConvertReport(grypeReportBytes)
	if err != nil {
		slog.Error("failed to convert trivy report", "error", err)
		os.Exit(1)
	}

	fmt.Println("Trivy Report:")
	for cve, vulnerabilities := range trivyReport {
		fmt.Printf("---\nCVE: %s\n", cve)
		for _, vuln := range vulnerabilities {
			fmt.Printf("PURL: %s\n", vuln.PURL)
			fmt.Printf("%+v\n", vuln)
		}
	}

	fmt.Println("\nGrype Report:")
	for cve, vulnerabilities := range grypeReport {
		fmt.Printf("---\nCVE: %s\n", cve)
		for _, vuln := range vulnerabilities {
			fmt.Printf("PURL: %s\n", vuln.PURL)
			fmt.Printf("%+v\n", vuln)
		}
	}
}

func generateSBOM(scanner types.ScannerType, image string) ([]byte, error) {
	switch scanner {
	case types.TRIVY:
		return trivy_helper.GenerateSBOM(image)
	case types.GRYPE:
		return grype_helper.GenerateSBOM(image)
	default:
		return nil, fmt.Errorf("unsupported scanner type")
	}
}

func generateReport(scanner types.ScannerType, sbomBytes []byte) ([]byte, error) {
	switch scanner {
	case types.TRIVY:
		return trivy_helper.GenerateReport(sbomBytes)
	case types.GRYPE:
		return grype_helper.GenerateReport(sbomBytes)
	default:
		return nil, fmt.Errorf("unsupported scanner type")
	}
}
