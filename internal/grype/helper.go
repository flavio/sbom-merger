package grype

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/anchore/clio"
	grype_cli "github.com/anchore/grype/cmd/grype/cli"
	syft_cli "github.com/anchore/syft/cmd/syft/cli"
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
