package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	trivyCommands "github.com/aquasecurity/trivy/pkg/commands"
	trivy_types "github.com/aquasecurity/trivy/pkg/types"
	"github.com/flavio/sbom-merger/internal/types"
)

func GenerateSBOM(image string) ([]byte, error) {
	log.Printf("Generating SBOM for image %s using Trivy", image)
	sbomFile, err := os.CreateTemp("", "trivy.sbom.*.json")
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

	app := trivyCommands.NewApp()
	app.SetArgs([]string{
		"image",
		"--format", "cyclonedx",
		"--db-repository", "public.ecr.aws/aquasecurity/trivy-db",
		"--java-db-repository", "public.ecr.aws/aquasecurity/trivy-java-db",
		"--output", sbomFile.Name(),
		image,
	})

	if err = app.ExecuteContext(context.TODO()); err != nil {
		return []byte{}, fmt.Errorf("failed to execute trivy: %w", err)
	}

	log.Printf("trivy SBOM generated")

	spdxBytes, err := io.ReadAll(sbomFile)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read SBOM output: %w", err)
	}

	log.Printf("trivy SBOM created successfully")

	return spdxBytes, nil
}

func GenerateReport(sbomBytes []byte) ([]byte, error) {
	sbomFile, err := os.CreateTemp("", "trivy.sbom.*.json")
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
	reportFile, err := os.CreateTemp("", "trivy.report.*.json")
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

	app := trivyCommands.NewApp()
	app.SetArgs([]string{
		"sbom",
		"--format", "json",
		// Use the public ECR repository to bypass GitHub's rate limits.
		// Refer to https://github.com/orgs/community/discussions/139074 for details.
		"--db-repository", "public.ecr.aws/aquasecurity/trivy-db",
		"--java-db-repository", "public.ecr.aws/aquasecurity/trivy-java-db",
		"--output", reportFile.Name(),
		sbomFile.Name(),
	})

	if err = app.ExecuteContext(context.TODO()); err != nil {
		return []byte{}, fmt.Errorf("failed to execute trivy: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read SBOM output: %w", err)
	}

	return reportBytes, nil
}

func ConvertReport(reportBytes []byte) (types.Vulnerabilities, error) {
	var trivyReport trivy_types.Report
	err := json.Unmarshal(reportBytes, &trivyReport)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal trivy report: %w", err)
	}

	return reportFromTryvy(trivyReport), nil
}

func reportFromTryvy(report trivy_types.Report) types.Vulnerabilities {
	vulnerabilities := make(types.Vulnerabilities)

	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			if _, exists := vulnerabilities[vulnerability.VulnerabilityID]; !exists {
				vulnerabilities[vulnerability.VulnerabilityID] = []types.Vulnerability{}
			}

			cvss := vulnerabilityCVSS(vulnerability)

			v := types.Vulnerability{
				VulnerabilityID:  vulnerability.VulnerabilityID,
				PackageName:      vulnerability.PkgName,
				PURL:             vulnerability.PkgIdentifier.PURL.ToString(),
				InstalledVersion: vulnerability.InstalledVersion,
				FixedVersions:    []string{vulnerability.FixedVersion},
				Status:           vulnerability.Status.String(),
				LayerDiffID:      vulnerability.Layer.DiffID,
				Title:            vulnerability.Title,
				Description:      vulnerability.Description,
				Severity:         vulnerability.Severity,
				Cvss:             cvss,
				References:       vulnerability.References,
			}

			vulnerabilities[v.VulnerabilityID] = append(vulnerabilities[v.VulnerabilityID], v)
		}
	}

	return vulnerabilities
}

func vulnerabilityCVSS(vulnerability trivy_types.DetectedVulnerability) types.CVSS {
	for _, cvss := range vulnerability.CVSS {
		// just return the first CVSS score and vector
		return types.CVSS{
			V3Score:  cvss.V3Score,
			V3Vector: cvss.V3Vector,
		}
	}

	return types.CVSS{
		V3Score:  0,
		V3Vector: "",
	}
}
