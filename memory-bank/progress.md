# Progress

*   **What Works:**
    *   Core Leeway build system functionality as described in `README.md`.
    *   Support for Go, Yarn, Docker, and generic packages.
    *   Local and remote caching (GCS/S3).
    *   Parallel builds based on dependency graph.
    *   Build arguments and constants.
    *   Component scripts.
    *   Dynamic package generation (`BUILD.js`).
    *   Rich CLI for inspection and interaction.
    *   Basic provenance generation (SLSA v0.2 - Experimental).
    *   Installation via pre-built binaries.
*   **What's Left:** (Based on initial assessment - requires deeper code analysis for specifics)
    *   Further development or refinement of existing features.
    *   Addressing any potential bugs or limitations not documented in the README.
    *   Stabilizing experimental features (e.g., Provenance).
    *   Potential new features or improvements.
*   **Current Status:** Project appears functional and released (mentions releases on GitHub). The core build system is implemented. Memory bank has just been initialized.
*   **Known Issues:**
    *   Windows is not supported.
    *   Requires GNU `coreutils` on macOS.
    *   Provenance feature is experimental.
    *   Potential performance issues with very large provenance bundles.
*   **Decision Evolution:** (Initial state - no evolution tracked yet)
    *   Decision to use content-based hashing for versioning.
    *   Decision to support Go, Yarn, Docker initially.
    *   Decision to implement two-level caching.
    *   Decision to use YAML for configuration.
