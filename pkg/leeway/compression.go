package leeway

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

var (
	compressor   = "gzip"
	decompressor = "gzip -d"
	// Number of CPU cores for parallel processing
	cpuCores = runtime.NumCPU()
)

func init() {
	// Check for pigz (parallel gzip) for faster compression
	pigz, err := exec.LookPath("pigz")
	if err == nil {
		// Use all available CPU cores by default
		compressor = fmt.Sprintf("%s -p %d", pigz, cpuCores)
	}
}

// CompressionAlgorithm represents supported compression algorithms
type CompressionAlgorithm string

const (
	Gzip    CompressionAlgorithm = "gzip"
	Zstd    CompressionAlgorithm = "zstd"
	NoCompr CompressionAlgorithm = "none"
)

// TarOptions represents configuration options for creating tar archives
type TarOptions struct {
	// OutputFile is the path to the output .tar or .tar.gz file
	OutputFile string

	// SourcePaths are the files/directories to include in the archive
	SourcePaths []string

	// WorkingDir changes to this directory before archiving (-C flag)
	WorkingDir string

	// UseCompression determines whether to apply compression
	UseCompression bool

	// CompressionAlgorithm specifies which algorithm to use
	CompressionAlgorithm CompressionAlgorithm

	// CompressionLevel allows setting compression level (1-9 for gzip/pigz)
	CompressionLevel int

	// FilesFrom specifies a file containing a list of files to include
	FilesFrom string

	// ExcludePatterns specifies patterns to exclude
	ExcludePatterns []string
}

// WithOutputFile sets the output file path for the tar archive
func WithOutputFile(path string) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.OutputFile = path
	}
}

// WithSourcePaths adds files or directories to include in the archive
func WithSourcePaths(paths ...string) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.SourcePaths = append(opts.SourcePaths, paths...)
	}
}

// WithWorkingDir sets the working directory for the tar command
func WithWorkingDir(dir string) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.WorkingDir = dir
	}
}

// WithCompression enables compression for the tar archive
func WithCompression(enabled bool) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.UseCompression = enabled
	}
}

// WithCompressionAlgorithm specifies which compression algorithm to use
func WithCompressionAlgorithm(algo CompressionAlgorithm) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.CompressionAlgorithm = algo
	}
}

// WithCompressionLevel sets the compression level
func WithCompressionLevel(level int) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.CompressionLevel = level
	}
}

// WithFilesFrom specifies a file containing the list of files to archive
func WithFilesFrom(filePath string) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.FilesFrom = filePath
	}
}

// WithExcludePatterns specifies patterns to exclude from the archive
func WithExcludePatterns(patterns ...string) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.ExcludePatterns = append(opts.ExcludePatterns, patterns...)
	}
}

// getCompressionCommand returns the appropriate compression command based on options
func getCompressionCommand(algo CompressionAlgorithm, level int) string {
	switch algo {
	case Zstd:
		if level > 0 {
			return fmt.Sprintf("zstd -%d", level)
		}
		return "zstd"
	case NoCompr:
		return ""
	default: // Gzip or fallback
		if level > 0 {
			return fmt.Sprintf("gzip -%d", level)
		}
		return compressor
	}
}

// getDecompressionCommand returns the appropriate decompression command based on file extension
func getDecompressionCommand(filename string) string {
	switch {
	case strings.HasSuffix(filename, ".gz"):
		return decompressor
	case strings.HasSuffix(filename, ".zst"):
		return "zstd -d"
	default:
		return ""
	}
}

// getFileExtension returns the appropriate file extension based on compression algorithm
func getFileExtension(algo CompressionAlgorithm) string {
	switch algo {
	case Zstd:
		return ".zst"
	case NoCompr:
		return ""
	default: // Gzip, Pigz or fallback
		return ".gz"
	}
}

// BuildTarCommand creates a platform-optimized tar command with the given options
func BuildTarCommand(options ...func(*TarOptions)) []string {
	// Initialize default options
	opts := &TarOptions{
		UseCompression:       true, // Default to using compression
		CompressionAlgorithm: Gzip, // Default to gzip
		CompressionLevel:     0,    // Default compression level (0 = default for the algorithm)
	}

	// Apply all option functions
	for _, option := range options {
		option(opts)
	}

	// Start building the command
	cmd := []string{"tar"}

	// Add verbose flag if needed
	// cmd = append(cmd, "-v")

	// Add Linux-specific optimizations
	if runtime.GOOS == "linux" {
		cmd = append(cmd, "--sparse")
	}

	// Handle files-from case specially
	if opts.FilesFrom != "" {
		cmd = append(cmd, "--files-from", opts.FilesFrom)
	}

	// Basic create command
	cmd = append(cmd, "-cf")

	// Add file extension based on compression algorithm if needed
	if opts.UseCompression && opts.CompressionAlgorithm != NoCompr {
		ext := getFileExtension(opts.CompressionAlgorithm)
		if !strings.HasSuffix(opts.OutputFile, ext) {
			opts.OutputFile = opts.OutputFile + ext
		}
	}
	cmd = append(cmd, opts.OutputFile)

	// Add working directory if specified
	if opts.WorkingDir != "" {
		cmd = append(cmd, "-C", opts.WorkingDir)
	}

	// Add exclude patterns if any
	for _, pattern := range opts.ExcludePatterns {
		cmd = append(cmd, "--exclude", pattern)
	}

	// Add compression if needed
	if opts.UseCompression && opts.CompressionAlgorithm != NoCompr {
		comprCmd := getCompressionCommand(opts.CompressionAlgorithm, opts.CompressionLevel)
		if comprCmd != "" {
			cmd = append(cmd, fmt.Sprintf("--use-compress-program=%v", comprCmd))
		}
	}

	// Add source paths (or "." if none specified)
	if len(opts.SourcePaths) > 0 {
		cmd = append(cmd, opts.SourcePaths...)
	} else {
		cmd = append(cmd, ".")
	}

	return cmd
}

// UnTarOptions represents configuration options for extracting tar archives
type UnTarOptions struct {
	// InputFile is the path to the .tar or .tar.gz file to extract
	InputFile string

	// TargetDir is the directory where files should be extracted
	TargetDir string

	// PreserveSameOwner determines whether to preserve file ownership
	PreserveSameOwner bool

	// AutoDetectCompression will check if the file is compressed
	AutoDetectCompression bool

	// Verbose enables verbose output
	Verbose bool

	// IncludePatterns specifies patterns to include during extraction
	IncludePatterns []string
}

// WithInputFile sets the input archive file path
func WithInputFile(path string) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.InputFile = path
	}
}

// WithTargetDir sets the directory where files will be extracted
func WithTargetDir(dir string) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.TargetDir = dir
	}
}

// WithPreserveSameOwner enables preserving file ownership
func WithPreserveSameOwner(preserve bool) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.PreserveSameOwner = preserve
	}
}

// WithAutoDetectCompression enables automatic detection of file compression
func WithAutoDetectCompression(detect bool) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.AutoDetectCompression = detect
	}
}

// WithVerboseExtraction enables verbose output during extraction
func WithVerboseExtraction(verbose bool) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.Verbose = verbose
	}
}

// WithIncludePatterns specifies patterns to include during extraction
func WithIncludePatterns(patterns ...string) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.IncludePatterns = append(opts.IncludePatterns, patterns...)
	}
}

// isCompressedFile checks if a file is compressed by examining its header
func isCompressedFile(filepath string) (CompressionAlgorithm, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return NoCompr, fmt.Errorf("failed to open file for compression detection: %w", err)
	}
	defer file.Close()

	// Read the first few bytes to check for magic numbers
	header := make([]byte, 4)
	_, err = file.Read(header)
	if err != nil {
		return NoCompr, fmt.Errorf("failed to read file header: %w", err)
	}

	// Check for gzip magic number (1F 8B)
	if header[0] == 0x1F && header[1] == 0x8B {
		return Gzip, nil
	}

	// Check for zstd magic number (28 b5 2f fd)
	if header[0] == 0x28 && header[1] == 0xb5 && header[2] == 0x2f && header[3] == 0xfd {
		return Zstd, nil
	}

	return NoCompr, nil
}

// BuildUnTarCommand creates a command to extract tar archives
func BuildUnTarCommand(options ...func(*UnTarOptions)) ([]string, error) {
	// Initialize default options
	opts := &UnTarOptions{
		PreserveSameOwner:     false, // Default to not preserving ownership
		AutoDetectCompression: true,  // Default to auto-detecting compression
		Verbose:               false, // Default to non-verbose output
	}

	// Apply all option functions
	for _, option := range options {
		option(opts)
	}

	// Start building the command
	cmd := []string{"tar"}

	// Add verbose flag if requested
	if opts.Verbose {
		cmd = append(cmd, "-v")
	}

	// Add Linux-specific optimizations
	if runtime.GOOS == "linux" {
		cmd = append(cmd, "--sparse")
	}

	// Basic extraction command
	cmd = append(cmd, "-xf", opts.InputFile)

	// Add ownership flag if needed
	if !opts.PreserveSameOwner {
		cmd = append(cmd, "--no-same-owner")
	}

	// Add target directory if specified
	if opts.TargetDir != "" {
		cmd = append(cmd, "-C", opts.TargetDir)
	}

	// Add include patterns if any
	cmd = append(cmd, opts.IncludePatterns...)

	// Handle compression if needed
	if opts.AutoDetectCompression {
		// First check by file extension for efficiency
		decomprCmd := getDecompressionCommand(opts.InputFile)

		// If no match by extension, try to detect by file header
		if decomprCmd == "" {
			comprAlgo, err := isCompressedFile(opts.InputFile)
			if err != nil {
				return nil, err
			}

			switch comprAlgo {
			case Gzip:
				decomprCmd = decompressor
			case Zstd:
				decomprCmd = "zstd -d"
			}
		}

		if decomprCmd != "" {
			cmd = append(cmd, fmt.Sprintf("--use-compress-program=%v", decomprCmd))
		}
	}

	return cmd, nil
}
