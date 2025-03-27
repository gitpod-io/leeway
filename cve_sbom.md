# Vulnerability Scanning and SBOM Generation for Gitpod Enterprise

# Introduction

---

Gitpod's [zero-trust security model](https://www.gitpod.io/solutions/supply-chain-security) is a key value proposition for our customers, particularly since Gitpod runs directly in their AWS accounts. As part of this commitment, customers increasingly expect comprehensive security practices including Software Bill of Materials (SBOM) generation and vulnerability scanning.

Currently, our approach to vulnerability scanning and SBOM generation is fragmented across repositories, with only portions of our infrastructure receiving automated scanning. This RFC proposes a systematic approach to enhance our security posture by implementing consistent vulnerability scanning and SBOM generation across our codebase.

## Goals

- Ensure zero critical CVEs in all Gitpod components through automated scanning and remediation
- Establish consistent SBOM generation for all repositories
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

## Repository Overview and Current Coverage

Gitpod consists of several key repositories with varying levels of security scanning:

| Repository | Purpose | Current Scanning | SBOM Generation |
| --- | --- | --- | --- |
| gitpod/gitpod | Core product (Classic) | None | None |
| gitpod/gitpod-next | Gitpod Flex | None | None |
| gitpod/gitpod-dedicated | Enterprise offering | None | None |
| gitpod/gitpod-dedicated-eks-ami | AWS AMI for Dedicated | Automated Trivy with build failure on critical CVEs | Automated with Trivy |
| gitpod/leeway | Build tool | None | None |

## Existing Processes

We have well-defined processes for handling vulnerabilities once they're detected ([Vulnerability Playbook](https://www.notion.so/Vulnerability-Playbook-d404a9dae6a24ca8997766d41d21d662?pvs=21)):

1. **Reporting**: Security vulnerabilities are reported to [security@gitpod.io](mailto:security@gitpod.io) and posted in the #security Slack channel
2. **Validation**: Engineering validates potential impact and likelihood
3. **Remediation**: Based on severity, vulnerabilities are addressed with defined timeframes:
    - Critical: 5 business days (24 hours for critical severity vulnerabilities)
    - High: 30 business days
    - Medium: 90 business days
    - Low: 180 business days
4. **Communication**: Clear communication paths for internal and external stakeholders

## Current Trivy Implementation

The [`gitpod/gitpod-dedicated-eks-ami`](https://github.com/gitpod-io/gitpod-dedicated-eks-ami) repository has the most mature vulnerability scanning approach:

- Configured to scan for HIGH and CRITICAL vulnerabilities
- Well-documented [ignore configurations](https://github.com/gitpod-io/gitpod-dedicated-eks-ami/blob/main/eks/files/trivy/trivyignore.yaml) with justifications for each exception
- Automated scanning during the build process
- Build failures when critical vulnerabilities are found
- Results preserved as artifacts
- Multiple scan types (vulnerabilities, SBOM, licenses)

## Key Gaps and Challenges

1. **Inconsistent Coverage**: Only one repository has automated scanning
2. **Ad-hoc Remediation**: No systematic approach to tracking and fixing vulnerabilities
3. **Missing SBOMs**: Limited SBOM generation capabilities
4. **Build Integration**: No integration with leeway build tool
5. **Manual Processes**: Current vulnerability handling is largely manual

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
    - Native SBOM generation in leeway
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

# Tool Analysis

---

This section evaluates different tools for vulnerability scanning and SBOM generation, with a focus on those mentioned in our discussions.

## Trivy

Trivy is our current tool in the gitpod/gitpod-dedicated-eks-ami repository and has proven effective.

### Strengths

- **Comprehensive scanning**: Detects vulnerabilities in OS packages and language-specific dependencies
- **Multiple scan types**: Supports vulnerability, license, and SBOM generation
- **Container-focused**: Excellent support for container image scanning
- **Active community**: Regularly updated vulnerability database
- **Integration options**: CI/CD integration, JSON output format
- **Performance**: Fast scanning with caching support

### Current Usage

Our current Trivy configuration in the EKS AMI repository provides a good template for expansion:

- Configured to scan for HIGH and CRITICAL severity issues
- Uses a detailed ignorefile with justifications
- Configured to skip specific directories
- Integrated with the build process for automatic scanning

## Docker SBOM (with Swyft)

Docker's built-in SBOM generation capability uses the Swyft library and focuses on creating accurate software bills of materials.

### Strengths

- **Native Docker integration**: Works directly with Docker CLI
- **Industry standard format**: Generates SBOMs in standard formats (SPDX, CycloneDX)
- **Simplicity**: Easier to use for basic SBOM generation
- **Developer familiarity**: Leverages existing Docker knowledge

### Limitations

- **Focus on SBOM**: Primarily designed for SBOM generation, not vulnerability scanning
- **Separate tools needed**: Requires pairing with other tools (like Docker Scout) for vulnerability assessment
- **Docker dependency**: Requires Docker to be present
- **Limited customization**: Fewer options for configuration

### Complementary Use

Docker SBOM could be used alongside Trivy, with each tool serving its primary purpose:

- Docker SBOM for generating detailed, standards-compliant SBOMs
- Trivy for comprehensive vulnerability scanning

## Comparison Matrix

| Feature | Trivy | Docker SBOM | Swyft Library Direct |
| --- | --- | --- | --- |
| Vulnerability Scanning | ✅ Comprehensive | ❌ Not the primary focus | ❌ Not the primary focus |
| SBOM Generation | ✅ Multiple formats | ✅ Industry standard | ✅ Flexible |
| License Scanning | ✅ Built-in | ✅ Supported | ✅ Supported |
| CI/CD Integration | ✅ Well-documented | ✅ Simple | ⚠️ Requires coding |
| Configuration Options | ✅ Extensive | ⚠️ Limited | ✅ Programmable |
| Performance | ✅ Fast with caching | ✅ Fast | ✅ Efficient |
| Leeway Compatibility | ⚠️ Requires integration | ⚠️ Requires integration | ✅ Could be embedded |
| Community Support | ✅ Active | ✅ Docker-backed | ⚠️ Library-level |

# Implementation Approach

---

This section outlines our approach to implementing comprehensive vulnerability scanning and SBOM generation across Gitpod's repositories.

## Guiding Principles

1. **Build on existing success**: Leverage the proven Trivy implementation in gitpod/gitpod-dedicated-eks-ami
2. **Automate where possible**: Minimize manual steps in security scanning and reporting
3. **Shift left**: Incorporate security scanning early in the development process
4. **Consistent policies**: Maintain uniform security standards across repositories
5. **Clear documentation**: Ensure all configurations and exceptions are well-documented

## Integration with Leeway

Based on leeway's architecture, we have several options for integrating security scanning. The analysis suggests that a post-build processing approach would be most effective, rather than introducing a plugin system.

### Leeway Integration Options

We have the following options for integrating security scanning into leeway:

### Option 1: Post-Build Processing

Leverage the existing `PostProcess` hook in leeway's build process:

- Runs after all build phases but before packaging
- Minimal changes to leeway's core code
- Clear separation between building and scanning
- Works well for Docker packages by using existing image extraction functionality

### Option 2: Direct Modification of Core Code

Add security scanning as a first-class feature in leeway:

- Full access to internal APIs and data structures
- Tighter integration with build process
- Unified configuration and reporting
- Requires more significant changes to the codebase

### Option 3: Wrapper Around Leeway

Create a wrapper script that invokes leeway and then performs security scanning:

- Non-invasive approach
- Can be developed independently
- Limited access to internal build state
- May miss some build artifacts or context

### Recommended Approach: Post-Build Processing with Path to First-Class Integration

We recommend starting with the Post-Build Processing approach while planning for potential first-class integration:

1. **Initial Implementation**:
    - Use the existing `PostProcess` hook for security scanning
    - Extend the provenance system to include SBOM data
    - Add configuration options to `WORKSPACE.yaml` and package `config` sections
2. **Configuration Structure**:
    
    ```yaml
      # In WORKSPACE.yaml
      securityScanning:
        enabled: true
        sbomGeneration: true
        vulnerabilityScanning: true
        failOnVulnerabilities: false
        scanners:
          - name: "trivy"
            config:
              severity: "HIGH,CRITICAL"
    ```
    
3. **Implementation Components**:
    - Modify `pkg/leeway/build.go` to add security scanning to the build process
    - Extend `pkg/leeway/provenance.go` to include SBOM data
    - Create new file `pkg/leeway/security.go` to implement scanning functionality

## Repository-Specific Strategies

Each repository requires a tailored approach based on its build process and deployment model:

### gitpod/gitpod (Classic)

1. **Immediate Approach (Before Leeway Integration)**:
    - Add Trivy scanning in GitHub Actions CI
    - Match configuration with gitpod-dedicated-eks-ami
    - Generate SBOMs for all container images
2. **After Leeway Integration**:
    - Use leeway's built-in security scanning
    - Ensure consistent behavior between CI and local builds

### gitpod/gitpod-dedicated

1. **CI Integration**:
    - Add Trivy scanning to GitHub Actions workflow
    - Focus on deployment artifacts
    - Configure to match our standard settings
2. **AMI Integration**:
    - Ensure consistent scanning between application and infrastructure

### gitpod/gitpod-next (Flex)

Leverage the same leeway integration as Classic, with adjustments for Flex-specific components.

## Notification and Reporting

To maintain visibility into security status:

1. **CI Integration**:
    - Fail builds on critical vulnerabilities
    - Generate warnings for high severity issues
2. **Slack Notifications**:
    - Send alerts when builds fail due to security issues
    - Provide summary of detected vulnerabilities
3. **Artifact Storage**:
    - Store scan results and SBOMs with build artifacts
    - Enable retrieval for customer requests and audits

## Exception Handling

Some vulnerabilities may need to be temporarily accepted:

1. **Exception Documentation**:
    - Require justification for each ignored vulnerability
    - Document remediation plan and timeline
    - Regular review of exceptions
2. **Configuration Strategy**:
    - Maintain ignore files in repository
    - Version control all security exceptions

## Scanner Configuration

For Trivy specifically, we'll standardize on the following configuration:

1. **Severity Levels**:
    - Scan for HIGH and CRITICAL vulnerabilities
    - Fail builds on CRITICAL vulnerabilities
2. **Ignore Configuration**:
    - Use detailed ignorefile with justifications
    - Configure to skip specific directories when needed
3. **Output Formats**:
    - JSON for machine processing
    - Table for human readability

# Implementation Plan

---

This section outlines a pragmatic, agile approach to implementing our vulnerability scanning and SBOM generation strategy.

## Phase 1: Quick Wins

**Focus**: Immediate security improvements with minimal overhead

### Key Tasks

1. **CI Integration for Core Repositories**
    - Add Trivy scanning to gitpod/gitpod and gitpod/gitpod-dedicated GitHub Actions workflow
    - Configure to match gitpod-dedicated-eks-ami settings
    - Set up Slack notifications for security failures
2. **Standardize Configuration**
    - Create reusable Trivy configuration files
    - Implement consistent ignorefile structure
    - Document pattern for handling exceptions
3. **Basic SBOM Generation**
    - Configure Trivy to generate SBOMs for all components
    - Store SBOMs as build artifacts

### Deliverables

- Working vulnerability scanning in CI for gitpod/gitpod and gitpod/gitpod-dedicated
- Standardized approach that can be applied to other repositories
- Documentation for developers on handling security findings

## Phase 2: Build System Integration

**Focus**: Deeper integration with minimal disruption

### Key Tasks

1. **Leeway Integration**
    - Implement security scanning using `PostProcess` hook
    - Add configuration options to `WORKSPACE.yaml`
    - Ensure compatibility with all package types
2. **Artifact Enhancement**
    - Store security information with build artifacts
    - Extend provenance system to include SBOMs
3. **Testing and Validation**
    - Verify scanning works across different package types
    - Ensure performance is acceptable for daily development

### Deliverables

- Security scanning integrated into the leeway build process
- SBOMs generated for all packages
- CI/CD pipeline that enforces security standards

## Phase 3: Customer-Facing Features (As needed)

**Focus**: Addressing specific customer requirements

### Key Tasks

1. **Customer Access**
    - Create simple approach for customers to access SBOMs
    - Document how customers can scan images themselves
2. **Process Refinement**
    - Tune configuration based on feedback
    - Implement automation for common remediation patterns

### Deliverables

- Customer-accessible security artifacts
- More efficient vulnerability management process

# Conclusion

---

This RFC outlines a pragmatic approach to improving vulnerability scanning and SBOM generation at Gitpod. By leveraging our existing successful implementation in gitpod/gitpod-dedicated-eks-ami and extending it to other repositories, we can enhance our security posture while meeting customer requirements.

Our approach prioritizes:

- Building on proven technologies like Trivy
- Integrating security scanning directly into our build processes
- Providing a phased implementation that delivers value quickly

The initial implementation can be completed relatively quickly, providing immediate security benefits while laying the groundwork for more comprehensive integration with our build system. This balanced approach addresses both our immediate security needs and long-term goals of providing customers with the security artifacts they require.

By implementing this plan, we will strengthen Gitpod's zero-trust security value proposition and provide customers with the transparency and assurance they expect when running our software in their AWS environments.
