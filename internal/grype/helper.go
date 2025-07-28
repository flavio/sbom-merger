package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/anchore/clio"
	grype_cli "github.com/anchore/grype/cmd/grype/cli"
	grype_types "github.com/anchore/grype/grype/presenter/models"
	syft_cli "github.com/anchore/syft/cmd/syft/cli"
	syft_file "github.com/anchore/syft/syft/file"
	"github.com/flavio/sbom-merger/internal/types"
)

func GenerateSBOM(image string) ([]byte, error) {
	log.Printf("generating SBOM for image %s with syft\n", image)

	sbomFile, err := os.CreateTemp("", "syft.sbom.*.json")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}
	defer func() {
		if err = sbomFile.Close(); err != nil {
			log.Printf("failed to close temporary SBOM file %v", err)
		}

		if err = os.Remove(sbomFile.Name()); err != nil {
			log.Printf("failed to remove temporary SBOM file %v", err)
		}
	}()

	id := clio.Identification{
		Name:    "sbombastic",
		Version: "0.1.0",
	}

	app := syft_cli.Command(id)
	app.SetArgs([]string{
		"scan",
		"--quiet",
		"--output", fmt.Sprintf("cyclonedx-json=%s", sbomFile.Name()),
		image,
	})

	if err = app.ExecuteContext(context.TODO()); err != nil {
		return []byte{}, fmt.Errorf("failed to execute syft: %w", err)
	}

	log.Printf("syft SBOM generated")

	spdxBytes, err := io.ReadAll(sbomFile)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read SBOM output: %w", err)
	}

	return spdxBytes, nil
}

func GenerateReport(sbomBytes []byte) ([]byte, error) {
	fmt.Println("generating report for image with grype")

	sbomFile, err := os.CreateTemp("", "grype.sbom.*.json")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}
	defer func() {
		if err = sbomFile.Close(); err != nil {
			log.Printf("failed to close temporary SBOM file: %v", err)
		}

		if err = os.Remove(sbomFile.Name()); err != nil {
			log.Printf("failed to remove temporary SBOM file: %v", err)
		}
	}()

	_, err = sbomFile.Write(sbomBytes)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to write SBOM file: %w", err)
	}
	reportFile, err := os.CreateTemp("", "grype.report.*.json")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create temporary report file: %w", err)
	}
	defer func() {
		if err = reportFile.Close(); err != nil {
			log.Printf("failed to close temporary report file: %v", err)
		}

		if err = os.Remove(reportFile.Name()); err != nil {
			log.Printf("failed to remove temporary repoort file: %v", err)
		}
	}()

	id := clio.Identification{
		Name:    "sbombastic",
		Version: "0.1.0",
	}

	app := grype_cli.Command(id)
	app.SetArgs([]string{
		"--quiet",
		"--output", fmt.Sprintf("json=%s", reportFile.Name()),
		fmt.Sprintf("sbom:%s", sbomFile.Name()),
	})

	if err = app.ExecuteContext(context.TODO()); err != nil {
		return []byte{}, fmt.Errorf("failed to execute grype: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read SBOM output: %w", err)
	}

	return reportBytes, nil
}

func ConvertReport(reportBytes []byte) (types.Vulnerabilities, error) {
	var document grype_types.Document
	err := json.Unmarshal(reportBytes, &document)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal grype report: %w", err)
	}

	return reportFromDocument(document), nil
}

func reportFromDocument(report grype_types.Document) types.Vulnerabilities {
	vulnerabilities := make(types.Vulnerabilities)

	for _, match := range report.Matches {
		cvss := vulnerabilityCVSS(match.Vulnerability.Cvss)

		layerDiffID := extractLocation(match.Artifact.Locations)

		v := types.Vulnerability{
			VulnerabilityID:  match.Vulnerability.ID,
			PackageName:      match.Artifact.Name,
			PURL:             match.Artifact.PURL,
			InstalledVersion: match.Artifact.Version,
			FixedVersions:    match.Vulnerability.Fix.Versions,
			Status:           match.Vulnerability.Fix.State,
			LayerDiffID:      layerDiffID,
			Title:            "", // Title is not present in grype report, so we leave it empty
			Description:      match.Vulnerability.Description,
			Severity:         match.Vulnerability.Severity,
			Cvss:             cvss,
			References:       match.Vulnerability.URLs,
		}

		vulnerabilities[v.VulnerabilityID] = append(vulnerabilities[v.VulnerabilityID], v)

	}

	return vulnerabilities
}

func extractLocation(locations syft_file.Locations) string {
	if len(locations) == 0 {
		return ""
	}

	return locations[0].Coordinates.FileSystemID
}

func vulnerabilityCVSS(cvss []grype_types.Cvss) types.CVSS {
	for _, cvss := range cvss {
		// just return the first CVSS score and vector of version 3.x
		if cvss.Version == "3.1" || cvss.Version == "3.0" {
			return types.CVSS{
				V3Score:  cvss.Metrics.BaseScore,
				V3Vector: cvss.Vector,
			}
		}
	}

	return types.CVSS{
		V3Score:  0,
		V3Vector: "",
	}
}
