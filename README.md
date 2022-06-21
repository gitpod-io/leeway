![Leeway](logo.png)

Leeway is a heavily caching build system for Go, Yarn and Docker projects.
Its features are:
- **source dependent versions**: leeway computes the version of a package based on the sources, dependencies and configuration that make up this package. There's no need (or means) to manually version packages.
- **two-level package cache**: leeway caches its build results locally and remotely. The remote cache (a Google Cloud Storage bucket) means builds can share their results and thus become drastically faster.
- **parallel builds**: because leeway understands the dependencies of your packages it can build them as parallel as possible.
- **built-in support for Yarn and Go**: leeway knows how to link, build and test Yarn and Go packages and applications. This makes building software written in those languages straight forward.
- **build arguments**: leeway supports build arguments which can parametrize packages at build time. We support version dependent arguments (where the version depends on the argument value), component-wide constants and workspace-level defaults.
- **rich CLI**: leeways CLI supports deep inspection of the workspace and its structure. Its output is easy to understand and looks good.

Leeway structures a repository in three levels:
- The **workspace** is the root of all operations. All component names are relative to this path. No relevant file must be placed outside the workspace. The workspace root is marked with a `WORKSPACE.yaml` file.
- A **components** is single piece of standalone software. Every folder in the workspace which contains a `BUILD.yaml` file is a component. Components are identifed by their path relative to the workspace root.
- **Packages** are the buildable unit in leeway. Every component can define multiple packages in its build file. Packages are identified by their name prefixed with the component name, e.g. some-component:pkg.

# Installation
Leeway assumes its running on Linux or macOS. It is very very unlikely that this runs on Windows out-of-the-box.
To install, just download and unpack a [release](https://github.com/gitpod-io/leeway/releases).

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
scripts:
- ...
```

## Package
A package is an entry in a `BUILD.yaml` in the `packages` section. All packages share the following fields:
```YAML
# name is the component-wide unique name of this package
name: must-not-contain-spaces
# Package type must be one of: go, yarn, docker, generic
type: generic
# Sources list all sources of this package. Entries can be double-star globs and are relative to the component root.
# Avoid listing sources outside the component folder.
srcs:
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

## Script
Scripts are a great way to automate tasks during development time (think [`yarn scripts`](https://classic.yarnpkg.com/en/docs/package-json#toc-scripts)).
Unlike packages they do not run in isolation by default, but have access to the original workspace.
What makes scripts special is that they can dependent on packages which become available to a script in the PATH and as environment variables.

Under the `scripts` key in the component's `BUILD.yaml` add:
```YAML
# name is the component-wide unique name of script. Packages and scripts do NOT share a namespace.
# You can have a package called foo and a script called foo within the same component.
name: some-script-name
# description provides a short synopsis of the script. Shown when running `leeway collect scripts`.
description: A sentence describing what the script is good for.
# Deps list dependencies to packages (NOT scripts) which must be built prior to running this script.
# All built dependencies get added to the PATH environment variable. This is handy if your workspace
# contains tools you want to use in a script.
deps:
- some/other:package
# Env sets environment variables which are present during script execution.
env:
- MESSAGE=hello
# Workdir changes the workdir location/layout of working dir of the script. The following choices are available:
# - origin (default): execute the script in the directory of the containing component in the original workspace.
#                     This is the default mode and handy if one wants to automate tasks in the development workspace.
# - packages:         produces a filesystem layout much like during a generic package build where all deps are
#                     found by their name in a temporary directory. This provides some isolation from the original
#                     workspace, while giving full access to the built dependencies.
workdir: origin
# The actual script. For now, only bash scripts are supported. The shebang is added automatically.
scrip: |
  echo $MESSAGE, this is where the script goes
  if [ "A$(ps -o comm= -p $$)" = "Abash" ]; then
    echo "it's the bash alright"
  fi
  echo "build args work to: ${myBuildArg}"
```

### Build arguments

In a package definition one can use _build arguments_. Build args have the form of `${argumentName}` and are string-replaced when the package is loaded.
**It's advisable to use build args only within the `config` section of packages**. Constants and built-in build args do not even work outside of the config section.

Leeway supports built-in build arguments:
- `__pkg_version` resolves to the leeway version hash of a component.

### Go packages
```YAML
config:
  # Packaging method. See https://godoc.org/github.com/gitpod-io/leeway/pkg/leeway#GoPackaging for details. Defaults to library.
  packaging: library
  # If true leeway runs `go generate -v ./...` prior to testing/building. Defaults to false.
  generate: false
  # If true disables `go test -v ./...`
  dontTest: false
  # If true disables the enforcement of `go fmt`. By default, if the code is not gofmt'ed the build fails.
  dontCheckGoFmt: false
  # If true disables the linting stage.
  dontLint: false
  # Overrides the `go build .` command. Supersedes buildFlags.
  buildCommand: []
  # [DEPRECATED: use buildCommand instead] A list of flags passed to `go build`. Useful for passing `ldflags`.
  buildFlags: []
  # Command that's executed to lint the code
  lintCommand: ["golangci-lint", "run"]
  # GoKart is a static security analysis tool for Go (https://github.com/praetorian-inc/gokart). leeway supports the construction
  # of analayzer.yaml file for GoKart based on the package dependencies. This is useful for detecing unsanitised input from API surfaces.
  gokart:
    enabled: false
    apiDepsPattern: 'reg-exp\/matching-go-package\/import-names'
```

### Yarn packages
```YAML
config:
  # yarnlock is the path to the yarn.lock used to build this package. Defaults to `yarn.lock`. Useful when building packages in a Yarn workspace setup.
  # Automatically added to the package sources.
  yarnlock: "yarn.lock"
  # tsconfig is the path to the tsconfig.json used to build this package. Detauls to `tsconfig.json`
  # Automatically added to the package sources.
  tsconfig: "tsconfig.json"
  # packaging method. See https://godoc.org/github.com/gitpod/leeway/pkg/leeway#YarnPackaging for details.
  # Defaults to library
  packaging: library
  # If true disables `yarn test`
  dontTest: false
  # commands overrides the default commands executed during build
  commands:
    install: ["yarn", "install"]
    build: ["yarn", "build"]
    test: ["yarn", "test"]
```

### Docker packages
Docker packages have a default "retagging" behaviour: even when a Docker package is built already, i.e. it's leeway version didn't change,
leeway will ensure that an image exists with the names specified in the package config. For example, if a Docker package has `leeway/some-package:${version}` specified,
and `${version}` changes, but otherwise the package has been built before, leeway will "re-tag" the previously built image to be available under `leeway/some-package:${version}`.
This behaviour can be disabled using `--dont-retag`.
```YAML
config:
  # Dockerfile is the name of the Dockerfile to build. Automatically added to the package sources.
  dockerfile: "Dockerfile"
  # Metadata produces a metadata.yaml file in the resulting package tarball.
  metadata:
    foo: bar
  # build args are Docker build arguments. Often we just pass leeway build arguments along here.
  buildArgs:
  - arg=value
  - other=${someBuildArg}
  # image lists the Docker tags leeway will use and push to
  image:
  - gitpod/leeway:latest
  - gitpod/leeway:${__pkg_version}
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

## Package Variants
Leeway supports build-time variance through "package variants". Those variants are defined on the workspace level and can modify the list of sources, environment variables and config of packages.
For example consider a `WORKSPACE.YAML` with this variants section:
```YAML
variants:
- name: nogo
  srcs:
    exclude:
    - "**/*.go"
  config:
    go:
      buildFlags:
        - tags: foo
```

This workspace has a (nonsensical) `nogo` variant that, when enabled, excludes all go source files from all packages.
It also changes the config of all Go packages to include the `-tags foo` flag. You can explore the effects of a variant using `collect` and `describe`, e.g. `leeway --variant nogo collect files` vs `leeway collect files`.
You can list all variants in a workspace using `leeway collect variants`.

## Environment Manifest
Leeway does not control the environment in which it builds the packages, but assumes that all required tools are available already (e.g. `go` or `yarn`).
This however can lead to subtle failure modes where a package built in one enviroment ends up being used in another, because no matter of the environment they were built in, they get the same version.

To prevent such issues, leeway computes an _environment manifest_ which contains the versions of the tools used, as well as some platform information.
The entries in that manifest depend on the package types used by that workspace, e.g. if only `Go` packages exist in the workspace, only `go version`, [GOOS and GOARCH](https://golang.org/pkg/runtime/#pkg-constants) will be part of the manifest.
You can inspect a workspace's environment manifest using `leeway describe environment-manifest`.

You can add your own entries to a workspace's environment manifest in the `WORKSPACE.yaml` like so:
```YAML
environmentManifest:
  - name: gcc
    command: ["gcc", "--version"]
```

Using this mechanism you can also overwrite the default manifest entries, e.g. "go" or "yarn".

## Nested Workspaces
Leeway has some experimental support for nested workspaces, e.g. a structure like this one:
```
/workspace
/workspace/WORKSPACE.yaml
/workspace/comp1/BUILD.yaml
/workspace/otherWorkspace/WORKSPACE.yaml
/workspace/otherWorkspace/comp2/BUILD.yaml
```

By default leeway would just ignore the nested `otherWorkspace/` folder and everything below, because of `otherWorkspace/WORKSPACE.yaml`. When nested workspace support is enabled though, the `otherWorkspace/` would be loaded as if it stood alone and merged into `/workspace`. For example:
```
$ export LEEWAY_NESTED_WORKSPACE=true
$ leeway collect
comp1:app
otherWorkspace/comp2:app
otherWorkspace/comp2:lib
```

- **inner workspaces are loaded as if they stood alone**: when leeway loads any nested workspace it does so as if that workspace stood for itself, i.e. were not nested. This means that all components are relative to that workspace root. In particular, dependencies remain stable no matter if a workspace is nested or not. E.g. `comp2:app` depending on `comp2:lib` works irregardless of workspace nesting.
- **nested dependencies**: dependencies from an oter workspace into a nested one are possible and behave as if all packages were in the same workspace, e.g. `comp1:app` could depend on `otherWorkspace/comp2:app`. Dependencies out of a nested workspace are not allowed, e.g. `otherWorkspace/comp2:app` cannot depend on `comp1:app`.
- **default arguments**: there is one exception to the "standalone", that is `defaultArgs`. The `defaultArgs` of the root workspace override the defaults of the nested workspaces. This is demonstrated by leeways test fixtures, where the message changes depending on the workspace that's loaded:
  ```
  $ export LEEWAY_NESTED_WORKSPACE=true
  $ leeway run fixtures/nested-ws/wsa/pkg1:echo
  hello world

  $ leeway run -w fixtures/nested-ws wsa/pkg1:echo
  hello root
  ```
- **variants**: only the root workspace's variants matter. Even if the nested workspace defined any, they'd simply be ignored.

# Configuration
Leeway is configured exclusively through the WORKSPACE.yaml/BUILD.yaml files and environment variables. The following environment
variables have an effect on leeway:
- `LEEWAY_WORKSPACE_ROOT`: Contains the path where to look for a WORKSPACE file. Can also be set using --workspace.
- `LEEWAY_REMOTE_CACHE_BUCKET`: Enables remote caching using GCP buckets. Set this variable to the bucket name used for caching. When this variable is set, leeway expects "gsutil" in the path configured and authenticated so that it can work with the bucket.
- `LEEWAY_CACHE_DIR`: Location of the local build cache. The directory does not have to exist yet.
- `LEEWAY_BUILD_DIR`: Working location of leeway (i.e. where the actual builds happen). This location will see heavy I/O which makes it advisable to place this on a fast SSD or in RAM.
- `LEEWAY_YARN_MUTEX`: Configures the mutex flag leeway will pass to yarn. Defaults to "network". See https://yarnpkg.com/lang/en/docs/cli/#toc-concurrency-and-mutex for possible values.
- `LEEWAY_EXPERIMENTAL`: Enables exprimental features
- `LEEWAY_NESTED_WORKSPACE`: Enables nested workspaces. By default leeway ignores everything below another `WORKSPACE.yaml`, but if this env var is set leeway will try and link packages from the other workspace as if they were part of the parent one. This does not work for scripts yet.

# Provenance (SLSA) - EXPERIMENTAL
leeway can produce provenance information as part of a build. At the moment only [SLSA](https://slsa.dev/spec/v0.1/) is supported. This supoprt is **experimental**.

Provenance generation is enabled in the `WORKSPACE.YAML` file.
```YAML
provenance:
  enabled: true
  slsa: true
```

Once enabled, all packages carry an [attestation bundle](https://github.com/in-toto/attestation/blob/main/spec/bundle.md) which is compliant to the [SLSA v0.2 spec](https://slsa.dev/provenance/v0.2) in their cached archive. The bundle is complete, i.e. not only contains the attestation for the package build, but also those of its dependencies.

## Dirty vs clean Git working copy
When building from a clean Git working copy, leeway will use a reference to the Git remote origin as [material](https://github.com/in-toto/in-toto-golang/blob/26b6a96f8a7537f27b7483e19dd68e022b179ea6/in_toto/model.go#L360) (part of the SLSA [link](https://github.com/slsa-framework/slsa/blob/main/controls/attestations.md)).

## Signing attestations
To support SLSA level 2, leeway can sign the attestations it produces. To this end, you can provide the filepath to a key either as part of the `WORKSPACE.yaml` or through the `LEEWAY_PROVENANCE_KEYPATH` environment variable.

## Inspecting provenance
You can inspect the generated attestation bundle by extracting it from the built and cached archive. For example:
```bash
# run a build
leeway build //:app

# export the attestation bundle
leeway provenance export //:app

# export the decoded attestation bundle
leeway provenance export --decode //:app

# verify that all material came from a Git repo
leeway provenance assert --git-only //:app

# verify that all subjects were built using leeway
leeway provenance asert --built-with-leeway //:app

# decode an attestation bundle from a file (also works for assertions)
leeway provenance export --decode file://some-bundle.jsonl
```

## Caveats
- provenance is part of the leeway package version, i.e. when you enable provenance that will naturally invalidate previously built packages.
- provenance is not supported for nested workspaces. The presence of `LEEWAY_NESTED_WORKSPACE` will make the build fail.
- if attestation bundle entries grow too large this can break the build process. Use `LEEWAY_MAX_PROVENANCE_BUNDLE_SIZE` to set the buffer size in bytes. This defaults to 2MiB. The larger this buffer is, the larger bundle entries can be used, but the more memory the build process will consume. If you exceed the default, inspect the bundles first (especially the one that fails to load) and see if the produced `subjects` make sense.

# Debugging
When a build fails, or to get an idea of how leeway assembles dependencies, run your build with `leeway build -c local` (local cache only) and inspect your `$LEEWAY_BUILD_DIR`.

# CLI tips

### How can I build a package in the current component/folder?
```bash
leeway build .:package-name
```

### Is there bash autocompletion?
Yes, run `. <(leeway bash-completion)` to enable it. If you place this line in `.bashrc` you'll have autocompletion every time.

### How can I find all packages in a workspace?
```bash
# list all packages in the workspace
leeway collect
# list all package names using Go templates
leeway collect -t '{{ range $n := . }}{{ $n.Metadata.FullName }}{{"\n"}}{{end}}'
# list all package names using jq
leeway collect -o json | jq -r '.[].metadata.name'
```

### How can I find out more about a package?
```bash
# print package description on the console
leeway describe some/components:package
# dump package description as json
leeway describe some/components:package -o json
```

### How can I inspect a packages depdencies?
```bash
# print the dependency tree on the console
leeway describe dependencies some/components:package
# print the denendency graph as Graphviz dot
leeway describe dependencies --dot some/components:package
# serve an interactive version of the dependency graph
leeway describe dependencies --serve=:8080 some/components:package
```

### How can I print a component constant?
```bash
# print all constants of the component in the current working directory
leeway describe const .
# print all constants of a component
leeway describe const some/component/name
# print the value of the `someName` constant of `some/component/name`
leeway describe const some/component/name -o json | jq -r '.[] | select(.name=="foo").value'
```

### How can I find all components with a particular constant?
```bash
leeway collect components -l someConstant
```

### How can I export only a workspace the way leeway sees it, i.e. based on the packages?
```bash
LEEWAY_EXPERIMENTAL=true leeway export --strict /some/destination
```
