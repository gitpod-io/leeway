Vulnerability Scanning and SBOM Generation for Gitpod Enterprise

# Introduction

---

Gitpod's [zero-trust security model](https://www.gitpod.io/solutions/supply-chain-security) is a key value proposition for our customers, particularly since Gitpod runs directly in their AWS accounts. As part of this commitment, customers increasingly expect comprehensive security practices including Software Bill of Materials (SBOM) generation and vulnerability scanning.

Currently, our approach to vulnerability scanning and SBOM generation is fragmented across repositories, with only portions of our infrastructure receiving automated scanning. This RFC proposes a systematic approach to enhance our security posture by implementing consistent vulnerability scanning and SBOM generation across our codebase.

## Goals

- Ensure zero critical CVEs in all Gitpod components through automated scanning (and remediation)
- Establish consistent SBOM generation for all components across all repositories
- Create clear processes for vulnerability detection, tracking, and remediation
- Enable customers to independently scan Gitpod images
- Integrate security scanning into our build processes
- Leverage existing automation where possible and extend to cover gaps

## Non-Goals

- Implementing intrusion detection systems
- Replacing existing security incident response processes
- Changing our SOC2 compliance framework
- Creating a bug bounty program

# Current State

We have well-defined processes for handling vulnerabilities once they're detected: [Vulnerability Playbook](https://www.notion.so/Vulnerability-Playbook-d404a9dae6a24ca8997766d41d21d662?pvs=21)

## Repository Overview and Current Coverage

Gitpod consists of several key repositories with varying levels of security scanning:

| Repository | Purpose | Current Scanning | SBOM Generation |
| --- | --- | --- | --- |
| gitpod/gitpod | Core product (Classic) | None | None |
| gitpod/gitpod-next | Gitpod Flex | None | None |
| gitpod/gitpod-dedicated | Enterprise offering | None | None |
| gitpod/gitpod-dedicated-eks-ami | AWS AMI for Dedicated | Automated Trivy with build failure on critical CVEs | Automated with Trivy |
| gitpod/leeway | Build tool | None | None |

What needs to be scanned for Gitpod Enterpise?

- Gitpod Classic Product (container images scan) → Build with Leeway
- Cell Side Lambdas (container images scan) → Build with Leeway
- Prerequisites (container images scan) → Kubernetes manifests
- AMI image (filesystem scan) → Not build with Leeway
    
    The [`gitpod/gitpod-dedicated-eks-ami`](https://github.com/gitpod-io/gitpod-dedicated-eks-ami) repository has the most mature vulnerability scanning approach:
    
    - Configured to scan for HIGH and CRITICAL vulnerabilities
    - Well-documented [ignore configurations](https://github.com/gitpod-io/gitpod-dedicated-eks-ami/blob/main/eks/files/trivy/trivyignore.yaml) with justifications for each exception
    - Automated scanning during the build process
    - Build failures when critical vulnerabilities are found
    - Results preserved as artifacts
    - Multiple scan types (vulnerabilities, SBOM, licenses)

# Objectives

---

This section outlines our short-term and long-term objectives for improving vulnerability scanning and SBOM generation at Gitpod.

## Short-Term Goals ("First Hill")

These are the immediate objectives we aim to achieve in the first phase of implementation:

1. **Implement Automated Scanning for Core Repositories**
    - Add automated Trivy scanning to gitpod/gitpod and gitpod/gitpod-decicated repository
    - Configure CI/CD to fail builds on critical vulnerabilities
    - Generate SBOMs for all container images
2. **Standardize Vulnerability Management Process**
    - Implement consistent ignore configurations with justifications
    - Set up Slack notifications when builds fail due to CVEs (similar to gitpod-dedicated-eks-ami)
3. **Leeway Integration**
    - Native SBOM generation in Leeway
    - Built-in vulnerability scanning for all leeway projects
    - Similar security configurations across repositories

## Long-Term Vision

These objectives represent our comprehensive security strategy to be implemented in subsequent phases:

1. **Customer Access to Security Artifacts**
    - Make SBOMs available to customers for all production images
    - Provide documentation on how customers can scan images themselves
    - Publish regular security reports for enterprise customers
2. **Comprehensive Automation**
    - Automated remediation for common vulnerability patterns
    - Automatic dependency updates when security patches are available

## Success Metrics

We will measure success through these key metrics:

1. **Coverage**:
    - 100% of container images and repositories scanned
    - 100% of production artifacts with associated SBOMs
2. **Remediation Efficiency**:
    - Zero critical vulnerabilities in production
    - High severity vulnerabilities remediated within timeframes
    - Consistent documentation of accepted risks
3. **Customer Satisfaction**:
    - Reduced security-related customer queries
    - Positive feedback on security practices
    - Security as a differentiating feature

# Scanning and SBOM Integration Approaches

---

To support both our internal need for CVE scanning and our customers' demand for SBOM delivery, we evaluated three alternative approaches for integrating vulnerability scanning and SBOM generation into our development workflow.

## Approach 1: Trivy in GitHub Actions (per-repo)

Run Trivy directly in each repository’s CI pipeline (e.g., GitHub Actions) immediately after the build step.

### ✅ Advantages

- **Simple to implement**: Requires minimal tooling and can be quickly added to CI workflows.
- **Flexible configuration**: Repos can adapt scanning rules to their own risk profile or environment.

### ❌ Disadvantages

- **Duplication across repos**: Every repository must implement and maintain its own scanning logic and ignore configuration.
- **Inconsistent behavior**: Harder to ensure all teams follow the same security standards or react similarly to scan results.
- **Limited reuse**: Doesn’t integrate with our build tool (`leeway`), so we can’t reuse logic or easily standardize SBOM delivery.

## Approach 2: Trivy integration in Leeway

Integrate Trivy into the Leeway build process. This would allow scanning to be configured centrally and executed uniformly across all repositories.

### ✅ Advantages

- **Standardized across projects**: Once implemented, all Leeway-based builds automatically include vulnerability scanning and SBOM generation.
- **Centralized configuration**: Security settings (e.g., severity thresholds, ignore rules) can be maintained in one place.
- **Consistent developer experience**: Developers using Leeway see the same behavior locally and in CI.

### ❌ Disadvantages

- **Requires Trivy binary**: Trivy needs to be present in the build environment, which increases build environment complexity.
- **CLI-based integration**: The integration relies on calling the Trivy CLI, which can be brittle and harder to test than embedding a Go library.
- **Trivy’s Go library is limited**: The maintainers recommend CLI usage, as the internal APIs are not stable.

## Approach 3: Native Syft + Grype Integration in Leeway

Integrate [Syft](https://github.com/anchore/syft) and [Grype](https://github.com/anchore/grype) — both developed by Anchore — directly into Leeway as Go libraries. SBOMs are generated using Syft, and CVE scanning is performed using Grype, both during the build process.

### ✅ Advantages

- **Native Go integration**: No need to shell out to CLI tools; uses stable and well-maintained Go libraries.
- **No external binaries required**: Simplifies the build environment and container setup.
- **Unified developer experience**: Everything runs inside Leeway, making the behavior consistent in CI and local builds.
- **Decoupled and modular**: Clean separation of SBOM generation (Syft) and CVE scanning (Grype), both embedded in code.

### ❌ Disadvantages

- **Less mature scanning ecosystem**: Trivy may have broader adoption and more mature policy features (e.g., license scanning, misconfig detection).
- **Embedded maintenance**: Requires deeper Go integration and more ongoing maintenance in Leeway.
- **Anchore-specific model**: Ties our tooling closer to the Syft/Grype ecosystem.

# SBOM and CVE Scan Delivery for Customers

---

Gitpod customers—especially enterprise users running Gitpod in their own environments—expect transparency and traceability over the components they're running. This includes access to:

- Software Bills of Materials (SBOMs)
- CVE scan results
- Scanning configuration and context

This section outlines what we will deliver and how.

## What We Deliver

We aim to provide the following artifacts for every Gitpod product release:

- **SBOMs** for all container images and core binaries
- **CVE scan results** for each component
- **Trivy/Grype configuration** used for the scans
- **Trivy/Grype ignore rules** (with justifications)
- **Trivy/Syft/Grype version** used to run the scans

These files provide the necessary inputs for customers to verify, audit, or replicate the security scanning process.

## Artifact Access Mechanism

### Proposal: Public S3 Bucket with Access Documentation

We propose storing SBOMs in a dedicated **S3 bucket** that is publicly readable, versioned, and structured by product and version.

We will include links and usage instructions in our documentation, e.g.,:

- How to download and verify SBOMs
- How to scan them using tools like [Trivy](https://github.com/aquasecurity/trivy) or [Grype](https://github.com/anchore/grype)

## Merging SBOMs Across Components

When each component (e.g., Docker image or binary) generates its own SBOM, the question arises whether we can combine these into a single, product-wide SBOM.

### Merging Feasibility

As of now, **Syft does not natively support merging multiple SBOMs** into one. This is a [known limitation tracked on GitHub](https://github.com/anchore/syft/issues/617?utm_source=chatgpt.com).

However, there are alternative approaches:

- Use the [CycloneDX CLI tool](https://github.com/CycloneDX/cyclonedx-cli) which supports merging multiple SBOMs in CycloneDX format
- Use custom scripts (e.g., `jq`) to merge SBOM files generated by Syft
- Example script and approach: [Merge two SBOMs with jq](https://edgebit.io/blog/merge-two-sboms/?utm_source=chatgpt.com)
    
    ```bash
    # Example: merge two Syft JSON SBOMs
    jq -s 'def deepmerge(a;b):
      reduce b[] as $item (a;
        reduce ($item | keys_unsorted[]) as $key (.;
          $item[$key] as $val | ($val | type) as $type | .[$key] = if ($type == "object") then
            deepmerge({}; [if .[$key] == null then {} else .[$key] end, $val])
          elif ($type == "array") then
            (.[$key] + $val | unique)
          else
            $val
          end)
        );
      deepmerge({}; .)' sbom1.json sbom2.json > combined.json
    ```
    

### Benefits of Merged SBOM

- **Simplifies consumption**: Easier for customers to scan and audit a single SBOM per release
- **Enables whole-product analysis**: Helps customers verify transitive dependencies across components
- **Streamlines automation**: Integrates well with tooling that expects a single SBOM file

### Considerations

- **Loss of granularity**: Component-level context (e.g., image name) may need to be preserved in the merged output
- **Merge tooling**: We’ll need to add a step post-build to collect and merge SBOMs
- **Format compatibility**: Merging works best if all SBOMs use the same schema (e.g., CycloneDX 1.5)

### Proposed Plan

1. Continue generating per-component SBOMs during the build (e.g., via Leeway or CI).
2. Add a new step (script or tool) in CI that:
    - Gathers all SBOMs for a given release
    - Merges them into a single combined SBOM
    - Publishes both individual and merged SBOMs to S3
3. Optionally include a `manifest.json` to index SBOM files and their components.

This approach ensures Gitpod can deliver high-quality, transparent SBOM data to our customers while keeping the internal build process modular and automated.

# Implemention Details for Integrating Syft + Grype in Leeway

---


Create a new package `pkg/leeway/sbom` to encapsulate the SBOM generation and CVE scanning functionality:

```
pkg/leeway/sbom/
├── sbom.go       # Core SBOM generation functionality
├── cve.go        # CVE scanning functionality
└── config.go     # Configuration structures
```

### Config

```go
// In pkg/leeway/sbom/config.go
type SBOMOptions struct {
    // SBOM generation options
    Format      string   // SBOM format (CycloneDX, SPDX) - default: CycloneDX
    OutputPath  string   // Where to store the SBOM - default: alongside build artifacts
}

type CVEOptions struct {
    // CVE scanning options
    FailOn           []string          // Severity levels to fail the build on - default: ["CRITICAL"]
    IgnoreRules      []IgnoreRule      // CVE ignore rules with documentation
    OutputPath       string            // Where to store the CVE report - default: alongside build artifacts
    IncludeMetadata  bool              // Whether to include metadata in the report - default: true
}

type IgnoreRule struct {
    ID          string   // CVE ID to ignore
    Reason      string   // Reason for ignoring this CVE
    Expiration  string   // Optional expiration date for this ignore rule
    Packages    []string // Optional list of packages this rule applies to
}

```

### Documented Ignore Rules

1. **YAML Configuration Format**:
    
    ```yaml
    # Example ignore rules in BUILD.yaml
    config:
      cve:
        ignoreRules:
          - id: "CVE-2023-1234"
            reason: "False positive in our usage context as we don't use the affected feature"
            expiration: "2025-12-31"  # Optional expiration date
            packages: ["pkg-name@1.2.3"]  # Optional specific packages
          - id: "CVE-2023-5678"
            reason: "Mitigated by our application architecture"
    
    ```
    
2. **Ignore File Generation**:
    - Generate a well-formatted ignore file alongside scan results
    - Include all metadata about the scan (tool versions, configuration used)
    - Store this file with the build artifacts

### Configurable Failure Thresholds

1. **Severity-Based Failure**:
    - Allow specifying which severity levels should fail the build
    - Default to failing only on CRITICAL vulnerabilities
    - Support multiple levels: CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE
2. **Configuration Options**:
    
    ```yaml
    # Global configuration in WORKSPACE.yaml
    sbom:
      failOn: ["CRITICAL", "HIGH"]  # Fail on critical and high vulnerabilities
    
    # Per-package configuration in BUILD.yaml
    config:
      cve:
        failOn: ["CRITICAL"]  # Override to fail only on critical
    
    ```
    
3. **CLI Override**:
    
    ```jsx
    leeway build --cve-fail-on=CRITICAL,HIGH component:package
    
    ```
    

### Metadata Storage

1. **Metadata File Contents**:
    
    ```json
    {
      "scanTime": "2025-03-28T14:30:00Z",
      "toolVersions": {
        "syft": "1.2.3",
        "grype": "0.9.8",
        "leeway": "0.7.0"
      },
      "configuration": {
        "failOn": ["CRITICAL"],
        "format": "CycloneDX",
        "ignoreRulesApplied": true},
      "package": "component:package",
      "packageVersion": "abcdef123456"
    }
    
    ```
    
2. **Ignore File Reference**:
    - Include a reference to the ignore file in the metadata
    - Document which rules were applied during the scan

### CLI Commands

```jsx
# Generate SBOM with options
leeway sbom generate [package] --format=cyclonedx --output=./sbom.json

# Scan with custom failure thresholds
leeway cve scan [package] --fail-on=CRITICAL,HIGH --ignore-file=./ignore.yaml

# Build with CVE scanning
leeway build [package] --cve-scan --cve-fail-on=CRITICAL

```

# Conclusion

---

This RFC outlines a pragmatic approach to improving vulnerability scanning and SBOM generation at Gitpod. By leveraging our existing successful implementation in `gitpod/gitpod-dedicated-eks-ami` and extending it to other repositories, we can enhance our security posture while meeting customer requirements.

Our approach prioritizes:

- Building on proven technologies like Trivy/Syft/Grype
- Integrating security scanning directly into our build processes
- Providing a phased implementation that delivers value quickly

The initial implementation can be completed relatively quickly, providing immediate security benefits while laying the groundwork for more comprehensive integration with our build system. This balanced approach addresses both our immediate security needs and long-term goals of providing customers with the security artifacts they require.

By implementing this plan, we will strengthen Gitpod's zero-trust security value proposition and provide customers with the transparency and assurance they expect when running our software in their AWS environments.
