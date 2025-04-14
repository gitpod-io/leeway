# System Patterns

*   **System Architecture:** Monolithic CLI application (`leeway`) managing builds within a structured workspace. The workspace contains components, and components define packages.
*   **Key Technical Decisions:**
    *   **Content-based Versioning:** Package versions are derived from source content, dependencies, and configuration, eliminating manual versioning.
    *   **Two-Level Caching:** Utilizes both local and remote (GCS/S3) caching to accelerate builds.
    *   **Dependency Graph:** Builds are parallelized based on the explicit dependency graph defined between packages.
    *   **Workspace Structure:** Enforces a three-level hierarchy (Workspace -> Component -> Package) marked by `WORKSPACE.yaml` and `BUILD.yaml` files.
    *   **Environment Manifest:** Captures tool versions and platform info to ensure build reproducibility across environments.
*   **Design Patterns:**
    *   **Configuration Files:** Uses YAML (`WORKSPACE.yaml`, `BUILD.yaml`) for defining workspace, components, and packages.
    *   **Build Scripts:** Supports `BUILD.js` for dynamic package generation.
    *   **CLI Interface:** Provides a rich command-line interface for interaction and inspection.
*   **Component Relationships:** Packages within components declare dependencies (`deps`) on other packages. Scripts can depend on packages. Docker packages can depend on other Docker packages, passing image names via build arguments.
*   **Critical Implementation Paths:**
    *   **Build Execution:** `leeway build <target>` triggers dependency resolution, cache checking, parallel execution, and caching of results.
    *   **Versioning:** Hashing sources, dependencies, config, and build arguments to compute a unique package version.
    *   **Caching:** Checking local and remote caches before building; storing results after successful builds.
    *   **Provenance Generation (Experimental):** Creating SLSA-compliant attestations during the build process.
