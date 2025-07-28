IMAGE=registry.k8s.io/ingress-nginx/controller:v1.12.0

#########
# trivy #
#########

trivy.sbom.spdx.json:
	@echo "Generating SPDX SBOM"
	trivy image --format spdx-json $(IMAGE) --output trivy.sbom.spdx.json
	@echo "SBOM generated at trivy.sbom.spdx.json"

trivy.sbom.cyclonedx.json:
	@echo "Generating cyclonedx-json SBOM"
	trivy image --format cyclonedx $(IMAGE) --output trivy.sbom.cyclonedx.json
	@echo "SBOM generated at trivy.sbom.cyclonedx.json"

trivy.report.sarif.json: trivy.sbom.cyclonedx.json
	@echo "Generating trivy report using sarif format"
	trivy sbom --format sarif --output trivy.report.sarif.json trivy.sbom.cyclonedx.json
	@echo "Report generated at trivy.report.sarif.json"

trivy.report.json: trivy.sbom.cyclonedx.json
	@echo "Generating trivy report using json format"
	trivy sbom --format json --output trivy.report.json trivy.sbom.cyclonedx.json
	@echo "Report generated at trivy.report.json"

#################
# syft && grype #
#################

syft.sbom.spdx.json:
	@echo "Generating syft SBOM using SPDX format"
	SYFT_GOLANG_MAIN_MODULE_VERSION_FROM_CONTENTS=true \
		syft scan $(IMAGE) --output spdx-json@2.2 | jq > syft.sbom.spdx.json
	@echo "SBOM generated at syft.sbom.spdx.json"

syft.sbom.cyclonedx.json:
	@echo "Generating syft SBOM using cyclonedx-json format"
	SYFT_GOLANG_MAIN_MODULE_VERSION_FROM_CONTENTS=true \
		syft scan $(IMAGE) --output cyclonedx-json | jq > syft.sbom.cyclonedx.json
	@echo "SBOM generated at syft.sbom.cyclonedx.json"

grype.report.sarif.json: syft.sbom.cyclonedx.json
	@echo "Generating grype report using sarif format"
	grype sbom:syft.sbom.cyclonedx.json --output sarif --by-cve | jq > grype.report.sarif.json
	@echo "Report generated at grype.report.sarif.json"

grype.report.json: syft.sbom.cyclonedx.json
	@echo "Generating grype report using json format"
	grype sbom:syft.sbom.cyclonedx.json --output json  --by-cve|  jq > grype.report.json
	@echo "Report generated at grype.report.json"

###########################
# Merge SBOMs and reports #
###########################

GO_SRCS := $(shell find ./ -type f -name '*.go')
sbom-merger: go.mod go.sum $(GO_SRCS)
	@echo "Building sbom-merger"
	go build -o sbom-merger
	@echo "sbom-merger built successfully"

.PHONY: clean
clean:
	rm -f *.json
	@echo "Cleaned up generated files"
