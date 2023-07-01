package handler

import "time"

type PackageSample struct {
	FullName         string
	DirtyWorkingCopy bool
	Status           PackageStatus
	Time             time.Time
	BuildDuration    time.Duration
}

type PackageStatus string

const (
	PackageStatusSuccess     PackageStatus = "success"
	PackageStatusFailed      PackageStatus = "failed"
	PackageStatusFailedTests PackageStatus = "failed_tests"
)
