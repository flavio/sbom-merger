This repository is a quick hack showing how to:

- Generate a cyclonedx SBOM using syft and trivy
- Generate a native json vulnerability report using grype and trivy, starting from the SBOM produced at an earlier stage. "Native json" means the proprietary format of the vulnerability scanner
- Navigate the reports using the native Go types of the two scanners
- Attempt to converge the results to a common type (**poorly done, still experimenting**)

I suggest to use the `registry.k8s.io/ingress-nginx/controller:v1.12.0` image as a test playground.
The image has some vulnerabilities affecting it, one of them is particularly important: `CVE-2025-1974`.
This vulnerability affects the `/nginx-ingress-controller` golang binary, which is not installed via a package manager. The vulnerability is coming from the project itself, not through
one of its dependencies. Because of that, trivy is not capable of detecting the vulnerability. On the opposite, grype can spot the vulnerability.
When merging the list of vulnerabilities we are expected to include this one into our final report.

The `Makefile` has some interesting targets:

- `make trivy.report.json`: produce a trivy native report. A cyclonedx SBOM is generated as an intermediate step
- `make grype.report.json`: produce a grype native report. A cyclonedx SBOM is generated with syft as an intermediate ste
- `make clean`: useful to clean all the reports and intermediate files.

The `IMAGE` env variable can be used to specify the name of the image to be scanned.

## grype json format

High level overview:

```yaml
{
  # list of matches
  "matches": [],
  # stats about grype, the db being used, the image that was scanned
  "source": {},
}
```

The relevant information are the list of matches inside of `.matches`.

A `match` entry is structured in this way:

```yaml
{
  # this includes vulnerability informations like:
  # - ID
  # - severity
  # - CVSS
  # - state
  "vulnerability": {},

  # I didn't see that being populated, probably just a matter of "bad luck"
  "relatedVulnerabilities": [],

  # this explains how the match was found. This seems something we can ignore,
  # since it's specific to grype.
  # Note: there are some useful information (like package name, version, suggested version
  # to fix the issue), however we can find all this information into the artifact section
  "matchDetails": [],

  # the details about the artifact that is affected by the vulnerability
  # this could be a system package or a binary that wasn't installed by
  # a package manager
  #
  # this includes information like:
  # - name
  # - version
  # - layerID <- from which container image layer the artifact comes from
  # - PURL
  "artifact": {},
}
```

Since a vulnerability can affect multiple packages, and a `match` is about one specific artifact,
inside of `.matches[]` there can be multiple entries for the same vulnerability, one per artifact that was found affected by it.

When a vulnerability affects an artifact installed by a package manager, the artifact data is going to be about that package. For example:

```yaml
{ "artifact": {
      "id": "pkg:apk/alpine/curl@8.11.1-r0?arch=x86_64&distro=alpine-3.21.0&package-id=537a80f4dd0b9337",
      "name": "curl",
      "version": "8.11.1-r0",
      "type": "apk",
      "locations":
        [
          {
            "path": "/lib/apk/db/installed",
            "layerID": "sha256:0b575ed2eb69c925e7f4fd53fef731203a7e91959211d9fad9fbed8094448fd2",
            "accessPath": "",
          },
        ],
      "language": "",
      "purl": "pkg:apk/alpine/curl@8.11.1-r0?arch=x86_64&distro=alpine-3.21.0",
      # other fields
    } }
```

However, when the vulnerability is affecting a library that has been used to build a "random binary" (something not
installed by a package manager), the artifact is going to talk about that library:

```yaml
{ "artifact": {
      "id": "pkg:golang/stdlib@1.23.4?package-id=ffbf38039d84c1a7",
      "name": "stdlib",
      "version": "go1.23.4",
      "type": "go-module",
      "locations":
        [
          {
            "path": "/dbg",
            "layerID": "sha256:6d134d3d7e8aa630874f7c4e9db3db48d1895c60f3e5ce73272412404a9b723b",
            "accessPath": "",
          },
        ],
      "language": "go",
      "purl": "pkg:golang/stdlib@1.23.4",
      # other fields
    } }
```

> [!IMPORTANT]
> Let's assume there's a vulnerability affecting the official Go stdlib and multiple Go binaries are shipped within the image (all of them
> built with the same version of Go). Then, there are going to be multiple `match` objects inside of the report about that stdlib vulnerability,
> one per Go binary shipped by the image.

## trivy json format

The report starts with some information that is not really useful to us, the critical information is inside of the `.Results[]` list.
This is a list of "result" objects.

Each result object is structured in this way:

```yaml
{
  # This value is a bit strange, see below
  "Target": "",

  # this is used to distinguish between system packages (installed by something like apt, apk, rpm,...) and "random binaries" found inside of
  # the image
  "Class": "",

  # this is for example the name of the linux distro (when type is a package manager) or something else for the other types of binaries
  "Type": "",

  # All the vulnerabilities affecting this group (target + class + type) or resources
  "Vulnerabilities": [],
}
```

For example, all the vulnerabilities affecting packages installed by a package manager are grouped
under this report:

```json
{
  "Target": "trivy.sbom.cyclonedx.json (alpine 3.21.0)",
  "Class": "os-pkgs",
  "Type": "alpine",
  "Vulnerabilities": []
}
```

> [!TIP]
> In this case the value of `Target` isn't useful. It's the name of the SBOM file that was inspected to produce the
> report.

This instead is an entry produced to describe all the vulnerabilities associated with a Go binary named `dbg`:

```json
{
  "Target": "dbg",
  "Class": "lang-pkgs",
  "Type": "gobinary",
  "Vulnerabilities": []
}
```

> [!TIP]
> In this case `Target` has valuable data, it contains the name of the binary affected.

Each `vulnerability` entry looks something like that (I've omitted the information we don't care about):

```yaml
{
  "VulnerabilityID": "CVE-2025-31498",
  "PkgName": "c-ares",
  "PkgIdentifier":
    {
      "PURL": "pkg:apk/alpine/c-ares@1.34.3-r0?arch=x86_64\u0026distro=3.21.0",
    },
  "InstalledVersion": "1.34.3-r0",
  "FixedVersion": "1.34.5-r0",
  "Status": "fixed",
  "Layer":
    {
      "DiffID": "sha256:96b9ae457f59557b462da6be6c9977b2d2db99437dcd13ee372f679b6d33241b",
    },
  "Title": "",
  "Description": "",
  "Severity": "",
  "CVSS": {},
  "References": [],
}
```

## Problem with PURL

[Package URL (aka PURL)](https://github.com/package-url/purl-spec)) is used to uniquely identify the source of the artifact.

When the vulnerability affects a Go binary, the PURL will be the very same one for all the binaries that are affected by that vulnerability.
That also means we cannot use PURL as a way to merge the report made by trivy with the one made by grype.

When using grype, we have to look into `.matches.artifact.locations[0].path` to get the name of the binary.

When using trivy, the name of the binary has to be inferred by looking at the combination of `result.Target`, `result.Class` and `result.Type`.

**Warning:** grype stores the absolute path to the binary, while trivy has only the name of the binary

> This can be seen searching for `CVE-2025-22871` inside of the reports generated by the Makefile of this project

## WIP

The `sbom-merger` tool attempts to convert the vulnerability reports produce by trivy and grype to a common
`Vulnerability` type defined by us.

The conversion is not complete and, most important, the final type is not settled yet.
