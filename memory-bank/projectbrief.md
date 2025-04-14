# Project Brief

*   **Core Requirements:** A heavily caching build system for Go, Yarn, and Docker projects featuring source-dependent versions, two-level caching (local and remote), parallel builds, built-in language support, build arguments, and a rich CLI.
*   **Goals:** Provide fast, reliable, and reproducible builds by automatically managing package versions based on content and dependencies, leveraging caching, and enabling parallel execution. Simplify the build process for Go, Yarn, and Docker projects.
*   **Scope:** Focuses on building Go, Yarn, and Docker projects within a defined workspace structure. Manages dependencies between packages within the workspace. Supports Linux and macOS environments. Includes features like build arguments, scripts, provenance generation (experimental), and workspace inspection via CLI. Excludes Windows support (explicitly mentioned).
*   **Source of Truth:** This document serves as the foundation for project scope and direction.
