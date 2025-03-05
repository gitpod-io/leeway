package remote

import (
	"context"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
)

type mockPackage struct {
	version string
	err     error
}

func (m mockPackage) Version() (string, error) {
	return m.version, m.err
}

func (m mockPackage) FullName() string {
	return "mock-package"
}

type mockLocalCache struct {
	locations map[string]string
}

func (m *mockLocalCache) Location(pkg cache.Package) (path string, exists bool) {
	version, err := pkg.Version()
	if err != nil {
		return "", false
	}
	path, exists = m.locations[version]
	return
}

func TestNewNoRemoteCache(t *testing.T) {
	t.Parallel()

	cache := NewNoRemoteCache()
	if cache == nil {
		t.Error("NewNoRemoteCache() returned nil")
	}
}

func TestExistingPackages(t *testing.T) {
	t.Parallel()

	noCache := NewNoRemoteCache()
	packages := []mockPackage{
		{version: "test1", err: nil},
		{version: "test2", err: nil},
	}

	var pkgs []cache.Package
	for i := range packages {
		pkgs = append(pkgs, packages[i])
	}

	result, err := noCache.ExistingPackages(context.Background(), pkgs)
	if err != nil {
		t.Errorf("ExistingPackages() error = %v", err)
	}

	if len(result) != 0 {
		t.Errorf("ExistingPackages() = %v, want empty map", result)
	}
}

func TestDownload(t *testing.T) {
	t.Parallel()

	noCache := NewNoRemoteCache()
	localCache := &mockLocalCache{
		locations: map[string]string{
			"test1": "/path/to/test1.tar.gz",
			"test2": "/path/to/test2.tar",
		},
	}
	packages := []mockPackage{
		{version: "test1", err: nil},
		{version: "test2", err: nil},
	}

	var pkgs []cache.Package
	for i := range packages {
		pkgs = append(pkgs, packages[i])
	}

	err := noCache.Download(context.Background(), localCache, pkgs)
	if err != nil {
		t.Errorf("Download() error = %v", err)
	}
}

func TestUpload(t *testing.T) {
	t.Parallel()

	noCache := NewNoRemoteCache()
	localCache := &mockLocalCache{
		locations: map[string]string{
			"test1": "/path/to/test1.tar.gz",
			"test2": "/path/to/test2.tar",
		},
	}
	packages := []mockPackage{
		{version: "test1", err: nil},
		{version: "test2", err: nil},
	}

	var pkgs []cache.Package
	for i := range packages {
		pkgs = append(pkgs, packages[i])
	}

	err := noCache.Upload(context.Background(), localCache, pkgs)
	if err != nil {
		t.Errorf("Upload() error = %v", err)
	}
}

func TestNoRemoteCacheImplementsInterface(t *testing.T) {
	t.Parallel()

	var _ cache.RemoteCache = (*NoRemoteCache)(nil)
}

// Ensure mockPackage implements cache.Package interface
var _ cache.Package = mockPackage{}

// Ensure mockLocalCache implements cache.LocalCache interface
var _ cache.LocalCache = (*mockLocalCache)(nil)
