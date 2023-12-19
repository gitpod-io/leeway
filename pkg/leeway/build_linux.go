package leeway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"
)

func checkForCpCompatibility() error {
	// we're on linux - just assume it's GNU cp
	return nil
}

func executeCommandsForPackageSafe(buildctx *buildContext, p *Package, wd string, commands [][]string) error {
	tmpdir, err := os.MkdirTemp("", "leeway-*")
	if err != nil {
		return err
	}

	jc, err := json.Marshal(commands)
	if err != nil {
		return err
	}
	commandsFN := filepath.Join(tmpdir, "commands")
	err = os.WriteFile(commandsFN, []byte(base64.StdEncoding.EncodeToString(jc)), 0644)
	if err != nil {
		return err
	}

	if !log.IsLevelEnabled(log.DebugLevel) {
		defer os.RemoveAll(tmpdir)
	}

	log.WithField("tmpdir", tmpdir).WithField("package", p.FullName()).Debug("preparing build runc environment")
	err = os.MkdirAll(filepath.Join(tmpdir, "rootfs"), 0755)
	if err != nil {
		return err
	}

	version, err := p.Version()
	if err != nil {
		return err
	}
	name := fmt.Sprintf("b%s", version)

	spec := specconv.Example()
	specconv.ToRootless(spec)

	// we assemble the root filesystem from the outside world
	for _, d := range []string{"home", "bin", "dev", "etc", "lib", "lib64", "opt", "sbin", "sys", "usr", "var"} {
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: "/" + d,
			Source:      "/" + d,
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		})
	}

	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/build", Source: wd, Type: "bind", Options: []string{"bind", "private"}})
	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/commands", Source: commandsFN, Type: "bind", Options: []string{"bind", "private"}})

	for _, p := range []string{"tmp", "root"} {
		fn := filepath.Join(tmpdir, p)
		err = os.MkdirAll(fn, 0777)
		if err != nil {
			return err
		}
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/" + p, Source: fn, Type: "bind", Options: []string{"bind", "private"}})
	}

	buildCache, _ := buildctx.LocalCache.Location(p)
	buildCache = filepath.Dir(buildCache)
	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: buildCache, Source: buildCache, Type: "bind", Options: []string{"bind", "private"}})

	self, err := os.Executable()
	if err != nil {
		return err
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/leeway", Source: self, Type: "bind", Options: []string{"bind", "private"}})

	if p := os.Getenv("GOPATH"); p != "" {
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: p, Source: p, Type: "bind", Options: []string{"bind", "private"}})
	}
	if p := os.Getenv("GOROOT"); p != "" {
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: p, Source: p, Type: "bind", Options: []string{"bind", "private"}})
	}
	if p := os.Getenv("DOCKER_HOST"); strings.HasPrefix(p, "file://") {
		p = strings.TrimPrefix(p, "file://")
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: p, Source: p, Type: "bind", Options: []string{"bind", "private"}})
	} else if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		p = "/var/run/docker.sock"
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: p, Source: p, Type: "bind", Options: []string{"bind", "private"}})
	}

	var env []string
	for _, e := range []string{"PATH", "TERM", "GOROOT", "GOPATH"} {
		val := os.Getenv(e)
		if val == "" {
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", e, val))
	}

	spec.Hostname = name
	spec.Process.Terminal = false
	spec.Process.NoNewPrivileges = true
	spec.Process.Args = []string{"/leeway", "plumbing", "exec", "/commands"}
	if log.IsLevelEnabled(log.DebugLevel) {
		spec.Process.Args = append(spec.Process.Args, "--verbose")

	}
	spec.Process.Cwd = "/build"
	spec.Process.Env = env

	fc, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(tmpdir, "config.json"), fc, 0644)
	if err != nil {
		return err
	}

	args := []string{
		"--root", "state",
		"--log-format", "json",
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		args = append(args, "--debug")
	}
	args = append(args,
		"run", name,
	)

	cmd := exec.Command("runc", args...)
	cmd.Dir = tmpdir
	cmd.Stdout = &reporterStream{R: buildctx.Reporter, P: p, IsErr: false}
	cmd.Stderr = &reporterStream{R: buildctx.Reporter, P: p, IsErr: true}
	return cmd.Run()
}
