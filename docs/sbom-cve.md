# SBOM Generation and CVE Scanning

Leeway provides built-in support for Software Bill of Materials (SBOM) generation and Common Vulnerabilities and Exposures (CVE) scanning. These features help you understand the components in your software and identify potential security vulnerabilities.

## Table of Contents

- [Overview](#overview)
- [SBOM Generation](#sbom-generation)
  - [Command-Line Usage](#sbom-command-line-usage)
  - [Build Integration](#sbom-build-integration)
  - [Supported Formats](#supported-formats)
- [CVE Scanning](#cve-scanning)
  - [Command-Line Usage](#cve-command-line-usage)
  - [Build Integration](#cve-build-integration)
  - [Severity Levels](#severity-levels)
  - [Ignore Rules](#ignore-rules)
- [Configuration](#configuration)
  - [SBOM Options](#sbom-options)
  - [CVE Options](#cve-options)
- [Examples](#examples)
  - [Generate SBOM](#generate-sbom)
  - [Scan for Vulnerabilities](#scan-for-vulnerabilities)
  - [Build with Security Scanning](#build-with-security-scanning)
  - [Ignore File Example](#ignore-file-example)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

Software Bill of Materials (SBOM) is a formal record of the components used in building your software. It provides transparency into your software supply chain, helping you understand what's in your software and where it came from.

CVE scanning identifies known vulnerabilities in your software components, allowing you to address security issues before they become problems.

Leeway integrates these features directly into the build process, making it easy to generate SBOMs and scan for vulnerabilities as part of your regular development workflow.

## SBOM Generation

### SBOM Command-Line Usage

To generate an SBOM for a package, use the `sbom` command:

```bash
leeway sbom <package> [flags]
```

Available flags:

- `-f, --format string`: SBOM format (cyclonedx, spdx) (default "cyclonedx")
- `-o, --output string`: Path to write the SBOM file

If no output path is specified, a summary of the SBOM will be printed to the console.

### SBOM Build Integration

To generate an SBOM during the build process, use the `--generate-sbom` flag with the `build` command:

```bash
leeway build <package> --generate-sbom [flags]
```

Additional flags for SBOM generation:

- `--sbom-format string`: SBOM format (cyclonedx, spdx) (default "cyclonedx")
- `--sbom-output string`: Path to write the SBOM file (defaults to `<package>-sbom.json` in the build directory)

### Supported Formats

Leeway supports the following SBOM formats:

- **CycloneDX**: A lightweight SBOM standard designed for use in application security contexts and supply chain component analysis.
- **SPDX**: A standard format for communicating the components, licenses, and copyrights associated with software packages.

## CVE Scanning

### CVE Command-Line Usage

To scan a package for vulnerabilities, use the `cve` command:

```bash
leeway cve <package> [flags]
```

Available flags:

- `--sbom-format string`: SBOM format (cyclonedx, spdx) (default "cyclonedx")
- `-o, --output string`: Path to write the vulnerability report
- `--fail-on stringSlice`: Severity levels to fail the build on (CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE) (default [CRITICAL])
- `--ignore-file string`: Path to a YAML file containing CVE ignore rules

If no output path is specified, a summary of the vulnerabilities will be printed to the console.

### CVE Build Integration

To scan for vulnerabilities during the build process, use the `--scan-cve` flag with the `build` command:

```bash
leeway build <package> --scan-cve [flags]
```

Additional flags for CVE scanning:

- `--cve-fail-on stringSlice`: Severity levels to fail the build on (CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE) (default [CRITICAL])
- `--cve-ignore-file string`: Path to a YAML file containing CVE ignore rules

### Severity Levels

Leeway uses the following severity levels for vulnerabilities:

- **CRITICAL**: Vulnerabilities that pose an immediate and severe risk
- **HIGH**: Vulnerabilities that pose a significant risk
- **MEDIUM**: Vulnerabilities that pose a moderate risk
- **LOW**: Vulnerabilities that pose a minor risk
- **NEGLIGIBLE**: Vulnerabilities that pose a minimal risk
- **UNKNOWN**: Vulnerabilities with an unknown severity level

### Ignore Rules

Ignore rules allow you to document and suppress specific vulnerabilities. This is useful for vulnerabilities that are not exploitable in your context or for which you have implemented mitigations.

Ignore rules are specified in a YAML file with the following format:

```yaml
ignoreRules:
  - id: CVE-2023-1234
    reason: "Not exploitable in our context because..."
    expiration: "2023-12-31T23:59:59Z"  # Optional
    packages:                           # Optional
      - package-name
```

Each ignore rule must include:

- `id`: The CVE ID to ignore
- `reason`: A documented reason for ignoring this vulnerability

Optional fields:

- `expiration`: An expiration date for the ignore rule (ISO 8601 format)
- `packages`: A list of packages to which this rule applies (if not specified, applies to all packages)

## Configuration

### SBOM Options

SBOM generation can be configured with the following options:

- **Format**: The SBOM format to use (cyclonedx, spdx)
- **OutputPath**: The path where the SBOM will be written

### CVE Options

CVE scanning can be configured with the following options:

- **FailOn**: Severity levels that will cause the build to fail
- **IgnoreRules**: Rules for ignoring specific vulnerabilities
- **OutputPath**: The path where the vulnerability report will be written
- **IncludeMetadata**: Whether to include metadata in the report

## Examples

### Generate SBOM

Generate a CycloneDX SBOM for a package:

```bash
leeway sbom components/server:app --format cyclonedx --output server-sbom.json
```

### Scan for Vulnerabilities

Scan a package for vulnerabilities, failing on CRITICAL and HIGH:

```bash
leeway cve components/server:app --fail-on CRITICAL,HIGH --ignore-file ignore.yaml
```

### Build with Security Scanning

Build a package with SBOM generation and CVE scanning:

```bash
leeway build components/server:app --generate-sbom --scan-cve --cve-fail-on CRITICAL
```

### Ignore File Example

```yaml
ignoreRules:
  - id: CVE-2023-1234
    reason: "Not exploitable in our context because the vulnerable component is not exposed to untrusted input."
    expiration: "2023-12-31T23:59:59Z"
    packages:
      - lodash

  - id: CVE-2023-5678
    reason: "Fixed in our custom patch, pending upstream fix."
    packages:
      - express
```

## Best Practices

- **Generate SBOMs for all components**: This provides transparency into your software supply chain.
- **Scan for vulnerabilities regularly**: This helps you identify and address security issues early.
- **Document ignore rules**: Always include a clear reason for ignoring a vulnerability.
- **Set expiration dates for ignore rules**: This ensures that ignored vulnerabilities are revisited.
- **Fail builds on critical vulnerabilities**: This prevents vulnerable code from being deployed.
- **Include SBOM generation and CVE scanning in CI/CD**: This ensures that security scanning is part of your development workflow.

## Troubleshooting

### Common Issues

#### SBOM Generation Fails

If SBOM generation fails, check:

- The package exists and can be built
- The package type is supported (Docker, Go, Yarn, Generic)
- You have sufficient permissions to write to the output path

#### CVE Scanning Fails

If CVE scanning fails, check:

- The SBOM was generated successfully
- The vulnerability database can be updated
- You have sufficient permissions to write to the output path

#### Build Fails Due to Vulnerabilities

If the build fails due to vulnerabilities, you can:

- Fix the vulnerabilities by updating the affected components
- Add ignore rules for vulnerabilities that are not exploitable in your context
- Adjust the severity levels that cause the build to fail

### Getting Help

If you encounter issues with SBOM generation or CVE scanning, please:

1. Check the documentation for the specific command or feature
2. Look for error messages in the output
3. File an issue on the Leeway GitHub repository with details about the problem
