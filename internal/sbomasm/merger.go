package sbomasm

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/interlynk-io/sbomasm/pkg/assemble"
	"github.com/interlynk-io/sbomasm/pkg/logger"
)

func cleanup(file *os.File) {
	if err := file.Close(); err != nil {
		log.Printf("failed to close temporary SBOM file %v", err)
	}

	if err := os.Remove(file.Name()); err != nil {
		log.Printf("failed to remove temporary SBOM file %v", err)
	}
}

func Merge(trivySBOM, syftSBOM []byte) ([]byte, error) {
	trivySbomFile, err := os.CreateTemp("", "trivy.sbom.*.json")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}

	syftSbomFile, err := os.CreateTemp("", "syft.sbom.*.json")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}

	if _, err = trivySbomFile.Write(trivySBOM); err != nil {
		return []byte{}, fmt.Errorf("failed to write trivy SBOM to file: %w", err)
	}
	if err = trivySbomFile.Close(); err != nil {
		return []byte{}, fmt.Errorf("failed to close trivy SBOM file: %w", err)
	}

	if _, err = syftSbomFile.Write(syftSBOM); err != nil {
		return []byte{}, fmt.Errorf("failed to write syft SBOM to file: %w", err)
	}
	if err = syftSbomFile.Close(); err != nil {
		return []byte{}, fmt.Errorf("failed to close syft SBOM file: %w", err)
	}

	defer func() {
		cleanup(trivySbomFile)
		cleanup(syftSbomFile)
	}()

	sbomMergedFile, err := os.CreateTemp("", "merged.sbom.*.json")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}

	logger.InitDebugLogger()
	ctx := logger.WithLogger(context.Background())

	assembleParams := assemble.Params{
		Input:         []string{trivySbomFile.Name(), syftSbomFile.Name()},
		Output:        sbomMergedFile.Name(),
		Ctx:           &ctx,
		Name:          "SBOMtastic",
		Version:       "0.1.0",
		Type:          "application",
		FlatMerge:     true,
		HierMerge:     false,
		AssemblyMerge: false,
		Xml:           false,
		Json:          true,
		OutputSpec:    "cyclonedx",
	}

	config, err := assemble.PopulateConfig(&assembleParams)
	if err != nil {
		return []byte{}, fmt.Errorf("error populating config: %w", err)
	}

	if err = assemble.Assemble(config); err != nil {
		return []byte{}, fmt.Errorf("error assembling SBOM: %w", err)
	}

	sbomBytes, err := os.ReadFile(sbomMergedFile.Name())
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read merged SBOM file: %w", err)
	}

	return sbomBytes, nil
}
