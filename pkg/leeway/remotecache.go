package leeway

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// RemoteCache can mirror the local build cache
type RemoteCache interface {
	// Get makes a best-effort attempt at downloading previously cached build artifacts for the given packages
	// in their current version. A cache miss (i.e. a build artifact not being available) does not constitute an
	// error. Get should try and download as many artifacts as possible.
	//
	// Get is expected to produce files named `<dest>/<key>`
	Get(dest string, keys []string) error

	// Put makes a best effort to upload the build arfitacts to a remote cache. If uploading an artifact fails, that
	// does not constitute an error.
	//
	// Put can expect to find files named `<source>/<key>`
	Put(source string, keys []string) error
}

// NoRemoteCache implements the default no-remote cache behavior
type NoRemoteCache struct{}

// Get makes a best-effort attempt at downloading previously cached build artifacts
func (NoRemoteCache) Get(dest string, keys []string) error {
	return nil
}

// Put makes a best effort to upload the build arfitacts to a remote cache
func (NoRemoteCache) Put(source string, keys []string) error {
	return nil
}

// GSUtilRemoteCache uses the gsutil command to implement a remote cache
type GSUtilRemoteCache struct {
	BucketName string
}

// Get makes a best-effort attempt at downloading previously cached build artifacts
func (rs GSUtilRemoteCache) Get(dest string, keys []string) error {
	log.Info("Checking remote cache for past build artifacts")
	files := make([]string, len(keys))
	for i, key := range keys {
		files[i] = fmt.Sprintf("gs://%s/%s", rs.BucketName, key)
	}
	return gsutilTransfer(dest, files)
}

// Put makes a best effort to upload the build arfitacts to a remote cache
func (rs GSUtilRemoteCache) Put(source string, keys []string) error {
	files := make([]string, len(keys))
	for i, key := range keys {
		files[i] = filepath.Join(source, key)
	}
	return gsutilTransfer(fmt.Sprintf("gs://%s", rs.BucketName), files)
}

func gsutilTransfer(target string, files []string) error {
	log.WithField("target", target).WithField("files", files).Debug("transfering files using gsutil")

	cmd := exec.Command("gsutil", "-m", "cp", "-I", target)
	cmd.Stdout = os.Stdout
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	err = cmd.Start()
	if err != nil {
		return err
	}

	for _, fn := range files {
		_, err = fmt.Fprintln(stdin, fn)
		if err != nil {
			return err
		}
	}
	err = stdin.Close()
	if err != nil {
		return err
	}

	err = cmd.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if _, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				// we just swallow non-zero exit codes here as remote caching is best effort
				return nil
			}
		}

		return err
	}
	return nil
}
