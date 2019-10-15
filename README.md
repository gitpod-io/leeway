![Leeway](logo.png)

Leeway is a heavily caching build system for Go, Typescript and Docker projects.
Its features are:
- **source dependent versions**: leeway computes the version of a package based on the sources, dependencies and configuration that make up this package. There's no need (or means) to manually version packages.
- **two-level package cache**: leeway caches its build results locally and remotely. The remote cache (a Google Cloud Storage bucket) means builds can share their results and thus become drastically faster.
- **parallel builds**: because leeway understands the dependencies of your packages it can build them as parallel as possible.
- **built-in support for Typescript and Go**: leeway knows how to link, build and test Typescript and Go packages and applications. This makes building software written in those languages straight forward.
- **build arguments**: leeway supports build arguments which can parametrize packages at build time. We support version dependent arguments (where the version depends on the argument value), component-wide constants and workspace-level defaults.
- **rich CLI**: leeways CLI supports deep inspection of the workspace and its structure. Its output is easy to understand and looks good.

Leeway structures a repository in three levels:
- The **workspace** is the root of all operations. All component names are relative to this path. No relevant file must be placed outside the workspace. The workspace root is marked with a `WORKSPACE.yaml` file.
- A **components** is single piece of standalone software. Every folder in the workspace which contains a `BUILD.yaml` file is a component. Components are identifed by their path relative to the workspace root.
- **Packages** are the buildable unit in leeway. Every component can define multiple packages in its build file. Packages are identified by their name prefixed with the component name, e.g. some-component:pkg.

# Installation
Leeway assumes its running on Linux or macOS. It is very very unlikely that this runs on Windows out-of-the-box.
To install, just download and unpack a [release](https://github.com/TypeFox/leeway/releases).

# Build setup

## Workspace
Place a file named `WORKSPACE.yaml` in the root of your workspace. For convenience sake you should set the `LEEWAY_WORKSPACE_ROOT` env var to the path of that workspace.
For example:
```
touch WORKSPACE.yaml
export LEEWAY_WORKSPACE_ROOT=$PWD
```

The `WORKSPACE.yaml` may contain some default settings for the workspace:
```YAML
# defaultTarget is package we build when just running `leeway build`
defaultTarget: some/package:name
#defaultArgs are key=value pairs setting default values for build arguments
defaultArgs:
  key: value
```

## Component
Place a `BUILD.yaml` in a folder somewhere in the workspace to make that folder a component. A `BUILD.yaml` primarily contains the packages of that components, but can also contain constant values (think of them as metadata). For example:
```YAML
# const defines component-wide constants which can be used much like build arguments. Only string keys and values are supported.
const:
  internalName: example
  someRandomProperty: value
packages:
- ...
```

## Package
A package is an entry in a `BUILD.yaml` in the `packages` section. All packages share the following fields:
```YAML
# name is the component-wide unique name of this package
name: must-not-contain-spaces
# Package type must be one of: go, typescript, docker, generic
type: generic
# Sources list all sources of this package. Entries can be double-star globs and are relative to the component root.
# Avoid listing sources outside the component folder.
sources:
- "**/*.yaml"
- "glob/**/path"
# Deps list dependencies to other packages which must be built prior to building this package. How these dependencies are made
# available during build depends on the package type.
deps:
- some/other:package
# Argdeps makes build arguments version relevant. I.e. if the value of a build arg listed here changes, so does the package version.
argdeps:
- someBuildArg
# Env is a list of key=value pair environment variables available during package build
env:
- CGO_ENABLED=0
# Config configures the package build depending on the package type. See below for details
config:
  ...
```

### Build arguments

In a package definition one can use _build arguments_. Build args have the form of `${argumentName}` and are string-replaced when the package is loaded.
**It's advisable to use build args only within the `config` section of packages**. Constants and built-in build args do not even work outside of the config section.

Leeway supports built-in build arguments:
- `__pkg_version` resolves to the leeway version hash of a component.

### Go packages
```YAML
config:
  # Packaging method. See https://godoc.org/github.com/TypeFox/leeway/pkg/leeway#GoPackaging for details. Defaults to library.
  packaging: library
  # If true leeway runs `go generate -v ./...` prior to testing/building. Defaults to false.
  generate: false
  # If true disables `go test -v ./...`
  dontTest: false
  # If true disables the enforcement of `go fmt`. By default, if the code is not gofmt'ed the build fails.
  dontCheckGoFmt: false
  # A list of flags passed to `go build`. Useful for passing `ldflags`.
  buildFlags: []
```

### Typescript packages
```YAML
config:
  # yarnlock is the path to the yarn.lock used to build this package. Defaults to `yarn.lock`. Useful when building packages in a Yarn workspace setup.
  # Automatically added to the package sources.
  yarnlock: "yarn.lock"
  # tsconfig is the path to the tsconfig.json used to build this package. Detauls to `tsconfig.json`
  # Automatically added to the package sources.
  tsconfig: "tsconfig.json"
  # packaging method. See https://godoc.org/github.com/TypeFox/leeway/pkg/leeway#TypescriptPackaging for details.
  # Defaults to library
  packaging: library
  # commands overrides the default commands executed during build
  commands:
    install: yarn install
    build: npx tsc
```

### Docker packages
```YAML
config:
  # Dockerfile is the name of the Dockerfile to build. Automatically added to the package sources.
  dockerfile: "Dockerfile"
  # build args are Docker build arguments. Often we just pass leeway build arguments along here.
  buildArgs:
  - arg=value
  - other=${someBuildArg}
  # image lists the Docker tags leeway will use and push to
  image:
  - typefox/leeway:latest
  - typefox/leeway:${__pkg_version}
```

### Generic packages
```YAML
config:
  # A list of commands to execute. Beware that the commands are not executed in a shell. If you need shell features (e.g. wildcards or pipes),
  # wrap your command in `sh -c`. Generic packages without commands result in an empty tar file.
  commands:
  - ["echo", "hello world"]
  - ["sh", "-c", "ls *"]
```

# Configuration
Leeway is configured exclusively through the WORKSPACE.yaml/BUILD.yaml files and environment variables. The following environment
variables have an effect on leeway:
- `LEEWAY_WORKSPACE_ROOT`: Contains the path where to look for a WORKSPACE file. Can also be set using --workspace.
- `LEEWAY_REMOTE_CACHE_BUCKET`: Enables remote caching using GCP buckets. Set this variable to the bucket name used for caching. When this variable is set, leeway expects "gsutil" in the path configured and authenticated so that it can work with the bucket.
- `LEEWAY_CACHE_DIR`: Location of the local build cache. The directory does not have to exist yet.
- `LEEWAY_BUILD_DIR`: Working location of leeway (i.e. where the actual builds happen). This location will see heavy I/O which makes it advisable to place this on a fast SSD or in RAM.
- `LEEWAY_YARN_MUTEX`: Configures the mutex flag leeway will pass to yarn. Defaults to "network". See https://yarnpkg.com/lang/en/docs/cli/#toc-concurrency-and-mutex for possible values.

# Debugging
When a build fails, or to get an idea of how leeway assembles dependencies, run your build with `leeway build -c local` (local cache only) and inspect your `$LEEWAY_BUILD_DIR`.
