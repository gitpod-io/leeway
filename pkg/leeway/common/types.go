package common

// PackageInfo contains basic information about a package
type PackageInfo struct {
	// FullName is the full name of the package
	FullName string

	// Version is the version of the package
	Version string

	// FilesystemSafeName is a filesystem-safe name for the package
	FilesystemSafeName string
}
