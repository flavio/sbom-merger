package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	grype_types "github.com/anchore/grype/grype/presenter/models"
	trivy_types "github.com/aquasecurity/trivy/pkg/types"
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

	var trivyReport trivy_types.Report
	err = json.Unmarshal(trivyReportBytes, &trivyReport)
	if err != nil {
		slog.Error("failed to unmarshal trivy report", "error", err)
		os.Exit(1)
	}
	fmt.Printf("Trivy SBOM generated for image %s with %d vulnerabilities\n", image, len(trivyReport.Results))

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

	var document grype_types.Document
	err = json.Unmarshal(grypeReportBytes, &document)
	if err != nil {
		slog.Error("failed to unmarshal grype report", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Syft SBOM generated for image %s with %d vulnerabilities\n", image, len(document.Matches))
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
