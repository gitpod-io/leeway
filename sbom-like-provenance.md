# Implementing SBOM Generation Similar to Provenance Generation

After examining the Leeway codebase, I can see that implementing SBOM generation similar to the provenance generation would significantly change the implementation approach described in the RFC. Let me explain what this would mean and how it would compare to the original plan.

## Current Provenance Implementation Pattern

The provenance implementation in Leeway follows this pattern:

1. **Configuration in Workspace**: The `WorkspaceProvenance` struct in the `Workspace` type controls provenance generation.
2. **Integration with Build Process**: The `writeProvenance` function is called during package builds to generate provenance data.
3. **Artifact Storage**: Provenance data is stored in a `provenance-bundle.jsonl` file within the build artifacts.
4. **Command Structure**: Dedicated commands (`provenance export`, `provenance assert`) provide ways to interact with the provenance data.
5. **Build Process Hook**: Provenance generation is integrated directly into the build process in `build.go`.

## What This Means for SBOM Implementation

Following this pattern for SBOM generation would involve:

1. **Workspace Configuration**:
   ```go
   type WorkspaceSBOM struct {
       Enabled bool `yaml:"enabled"`
       Format  string `yaml:"format,omitempty"` // e.g., "cyclonedx", "spdx"
       ScanCVE bool `yaml:"scanCVE"`
       FailOn  []string `yaml:"failOn,omitempty"` // e.g., ["CRITICAL", "HIGH"]
   }
   ```
   Added to the `Workspace` struct.

2. **Build Process Integration**:
   - Create a `writeSBOM` function similar to `writeProvenance`
   - Call this function during the build process
   - Optionally run CVE scanning if enabled

3. **Artifact Storage**:
   - Store SBOM data in a file like `sbom.json` or `sbom.cyclonedx.json`
   - Include this file in the package archive

4. **Command Structure**:
   - Add `sbom export` command to extract SBOM from packages
   - Add `sbom scan` command to perform vulnerability scanning
   - Add `sbom validate` command to validate SBOM format

## Comparison with RFC Approach

| Aspect | RFC Approach (pkg/leeway/sbom) | Provenance-like Approach |
|--------|--------------------------------|--------------------------|
| **Code Organization** | Separate package with dedicated files | Integrated directly into existing build code |
| **Configuration** | Separate config structures | Part of Workspace configuration |
| **Integration** | Called via build options | Built into the build process |
| **Flexibility** | More modular, easier to extend | More tightly coupled with build process |
| **Consistency** | New pattern | Consistent with existing patterns |
| **Maintenance** | Isolated changes | Changes spread across codebase |

## Implementation Considerations

1. **SBOM Generation Timing**: Like provenance, SBOM generation would happen after the build is complete but before packaging.

2. **Package Type Handling**: Different package types (Go, Yarn, Docker, Generic) would need specific SBOM generation logic.

3. **Workspace Configuration**:
   ```yaml
   # Example WORKSPACE.yaml configuration
   sbom:
     enabled: true
     format: cyclonedx
     scanCVE: true
     failOn: ["CRITICAL"]
   ```

4. **Build Process Integration**:
   ```go
   // In build.go, similar to how provenance is handled
   if p.C.W.SBOM.Enabled {
       if err := writeSBOM(p, buildctx, builddir, now); err != nil {
           return err
       }
       
       if p.C.W.SBOM.ScanCVE {
           if err := scanSBOMForVulnerabilities(p, buildctx, builddir); err != nil {
               return err
           }
       }
   }
   ```

5. **Command Structure**:
   ```go
   // sbom.go (similar to provenance.go)
   var sbomCmd = &cobra.Command{
       Use:     "sbom <command>",
       Short:   "Commands for working with Software Bill of Materials",
       Args:    cobra.MinimumNArgs(1),
       Aliases: []string{"bom"},
   }
   
   // sbom-export.go, sbom-scan.go, etc.
   ```

## Technical Implementation Path

1. Add SBOM configuration to `Workspace` struct
2. Create SBOM generation functions using Syft
3. Integrate SBOM generation into the build process
4. Add CVE scanning using Grype
5. Create CLI commands for SBOM operations
6. Add documentation

## My Assessment

The provenance-like approach has several advantages:

1. **Consistency**: It follows established patterns in the codebase
2. **Integration**: It's more tightly integrated with the build process
3. **Familiarity**: Developers familiar with provenance will understand SBOM generation

However, it also has some drawbacks:

1. **Coupling**: Changes are more spread out across the codebase
2. **Flexibility**: It may be harder to extend or modify independently
3. **Complexity**: The build process becomes more complex with additional responsibilities
