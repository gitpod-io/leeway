package testing

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
)

// MockLocalCache implements a in-memory LocalCache for testing
type MockLocalCache struct {
	files map[string][]byte
	mu    sync.RWMutex
}

// NewMockLocalCache creates a new mock local cache
func NewMockLocalCache() *MockLocalCache {
	return &MockLocalCache{
		files: make(map[string][]byte),
	}
}

// Location implements LocalCache
func (m *MockLocalCache) Location(pkg cache.Package) (path string, exists bool) {
	version, err := pkg.Version()
	if err != nil {
		return "", false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check for .tar.gz first
	gzPath := fmt.Sprintf("%s.tar.gz", version)
	if _, ok := m.files[gzPath]; ok {
		return gzPath, true
	}

	// Fall back to .tar
	tarPath := fmt.Sprintf("%s.tar", version)
	_, exists = m.files[tarPath]
	return tarPath, exists
}

// AddFile adds a file to the mock cache
func (m *MockLocalCache) AddFile(path string, content []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = content
}

// MockObjectStorage implements ObjectStorage interface for testing
type MockObjectStorage struct {
	objects map[string][]byte
	mu      sync.RWMutex
}

// NewMockObjectStorage creates a new mock object storage
func NewMockObjectStorage() *MockObjectStorage {
	return &MockObjectStorage{
		objects: make(map[string][]byte),
	}
}

// HasObject implements ObjectStorage
func (m *MockObjectStorage) HasObject(ctx context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.objects[key]
	return exists, nil
}

// GetObject implements ObjectStorage
func (m *MockObjectStorage) GetObject(ctx context.Context, key string, dest string) (int64, error) {
	m.mu.RLock()
	content, exists := m.objects[key]
	m.mu.RUnlock()

	if !exists {
		return 0, fmt.Errorf("object not found: %s", key)
	}

	return int64(len(content)), nil
}

// UploadObject implements ObjectStorage
func (m *MockObjectStorage) UploadObject(ctx context.Context, key string, src string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = []byte(fmt.Sprintf("mock content for %s", key))
	return nil
}

// ListObjects implements ObjectStorage
func (m *MockObjectStorage) ListObjects(ctx context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []string
	for key := range m.objects {
		if matched, _ := filepath.Match(prefix+"*", key); matched {
			result = append(result, key)
		}
	}
	return result, nil
}

// AddObject adds an object to the mock storage
func (m *MockObjectStorage) AddObject(key string, content []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = content
}
