package trivy

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	trivyCommands "github.com/aquasecurity/trivy/pkg/commands"
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
