package types

type ScannerType int

const (
	TRIVY ScannerType = iota
	GRYPE
)

func (s ScannerType) String() string {
	switch s {
	case TRIVY:
		return "trivy"
	case GRYPE:
		return "grype"
	default:
		return "unknown"
	}
}
