package openclarity

import (
	"bytes"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	scanner_types "github.com/flavio/sbom-merger/internal/types"
	"github.com/openclarity/openclarity/scanner/common"
	"github.com/openclarity/openclarity/scanner/families/sbom/types"
)

func Merge(trivySBOM, syftSBOM []byte) ([]byte, error) {
	trivyScannerResults, err := createScannerResult(bytes.NewReader(trivySBOM), scanner_types.TRIVY.String(), "SBOMtastic")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create trivy scan results: %w", err)
	}
	syftScannerResults, err := createScannerResult(bytes.NewReader(syftSBOM), scanner_types.GRYPE.String(), "SBOMtastic")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create syft scan results: %w", err)
	}

	mergedResults := newMergedResults(common.SBOM, "fake-hash")
	mergedResults = mergedResults.Merge(trivyScannerResults)
	mergedResults = mergedResults.Merge(syftScannerResults)

	sbomBytes, err := mergedResults.CreateMergedSBOMBytes("cyclonedx-json", "1.2.3")
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create merged sbom: %w", err)
	}
	return sbomBytes, nil
}

func createScannerResult(reader io.Reader, analyzerName, userInput string) (*types.ScannerResult, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(reader, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("failed to decode sbom: %w", err)
	}

	return types.CreateScannerResult(bom, analyzerName, userInput, common.SBOM), nil
}
