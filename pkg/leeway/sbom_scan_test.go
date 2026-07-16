package leeway

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/google/go-cmp/cmp"

	leewaycache "github.com/gitpod-io/leeway/pkg/leeway/cache"
)

func TestVulnerabilityDBLoaderLoad(t *testing.T) {
	t.Parallel()

	type Expectation struct {
		Calls  int
		Sleeps []time.Duration
		Err    string
	}

	tests := []struct {
		Name       string
		LoadErrors []string
		Expected   Expectation
	}{
		{
			Name:       "loads_on_first_attempt",
			LoadErrors: []string{""},
			Expected: Expectation{
				Calls: 1,
			},
		},
		{
			Name:       "retries_with_bounded_backoff",
			LoadErrors: []string{"temporary failure", "temporary failure", ""},
			Expected: Expectation{
				Calls:  3,
				Sleeps: []time.Duration{time.Second, 2 * time.Second},
			},
		},
		{
			Name:       "returns_last_error_after_max_attempts",
			LoadErrors: []string{"first failure", "second failure", "final failure"},
			Expected: Expectation{
				Calls:  3,
				Sleeps: []time.Duration{time.Second, 2 * time.Second},
				Err:    "failed to load vulnerability database after 3 attempts: final failure",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			var got Expectation
			loader := vulnerabilityDBLoader{
				maxAttempts:    3,
				initialBackoff: time.Second,
				sleep: func(delay time.Duration) {
					got.Sleeps = append(got.Sleeps, delay)
				},
				load: func() (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
					loadErr := tc.LoadErrors[got.Calls]
					got.Calls++
					if loadErr != "" {
						return nil, nil, errors.New(loadErr)
					}
					return nil, &vulnerability.ProviderStatus{}, nil
				},
			}

			buildctx := &buildContext{buildOptions: buildOptions{Reporter: &NoopReporter{}}}
			_, _, err := loader.Load(buildctx, NewTestPackage("scan"))
			if err != nil {
				got.Err = err.Error()
			}

			if diff := cmp.Diff(tc.Expected, got); diff != "" {
				t.Errorf("vulnerabilityDBLoader.Load() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestScanAllPackagesForVulnerabilitiesReusesScanner(t *testing.T) {
	t.Parallel()

	type Expectation struct {
		FactoryCalls     int
		ScannedPackages  []string
		CloseCalls       int
		CloseErrorLogged bool
		Err              string
	}

	tests := []struct {
		Name           string
		PackageStatus  PackageBuildStatus
		FactoryErr     string
		ScanErrPackage string
		CloseErr       string
		Expected       Expectation
	}{
		{
			Name: "reuses_and_closes_one_scanner",
			Expected: Expectation{
				FactoryCalls:    1,
				ScannedPackages: []string{"testcomp:first", "testcomp:second"},
				CloseCalls:      1,
			},
		},
		{
			Name:          "skips_scanner_without_scannable_packages",
			PackageStatus: PackageNotBuiltYet,
			Expected:      Expectation{},
		},
		{
			Name:       "stops_when_scanner_initialization_fails",
			FactoryErr: "database unavailable",
			Expected: Expectation{
				FactoryCalls: 1,
				Err:          "failed to initialize vulnerability scanner: database unavailable",
			},
		},
		{
			Name:           "keeps_scanning_after_package_failure",
			ScanErrPackage: "testcomp:first",
			Expected: Expectation{
				FactoryCalls:    1,
				ScannedPackages: []string{"testcomp:first", "testcomp:second"},
				CloseCalls:      1,
				Err:             "vulnerability scan failed for packages: testcomp:first",
			},
		},
		{
			Name:     "logs_scanner_close_failure",
			CloseErr: "close failure",
			Expected: Expectation{
				FactoryCalls:     1,
				ScannedPackages:  []string{"testcomp:first", "testcomp:second"},
				CloseCalls:       1,
				CloseErrorLogged: true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			var got Expectation
			reporter := &sbomScanRecordingReporter{}
			buildctx := &buildContext{buildOptions: buildOptions{
				Reporter:   reporter,
				LocalCache: sbomScanTestCache{},
			}}

			packages := []*Package{NewTestPackage("first"), NewTestPackage("second")}
			pkgstatus := make(map[*Package]PackageBuildStatus, len(packages))
			packageStatus := tc.PackageStatus
			if packageStatus == "" {
				packageStatus = PackageBuilt
			}
			for _, pkg := range packages {
				pkg.C.W.SBOM.Enabled = true
				artifactPath := filepath.Join(t.TempDir(), pkg.FilesystemSafeName()+".tar.gz")
				if err := os.WriteFile(artifactPath+".sbom.cdx.json", []byte("{}"), 0644); err != nil {
					got.Err = "test setup: " + err.Error()
					break
				}
				buildctx.LocalCache.(sbomScanTestCache)[pkg.FullName()] = artifactPath
				pkgstatus[pkg] = packageStatus
			}

			scanner := &fakeSBOMVulnerabilityScanner{
				scanErrPackage: tc.ScanErrPackage,
				closeErr:       tc.CloseErr,
			}
			factory := func(_ *buildContext, _ *Package) (sbomVulnerabilityScanner, error) {
				got.FactoryCalls++
				if tc.FactoryErr != "" {
					return nil, errors.New(tc.FactoryErr)
				}
				return scanner, nil
			}

			if got.Err == "" {
				err := scanAllPackagesForVulnerabilitiesWithScannerFactory(buildctx, packages, pkgstatus, factory, t.TempDir())
				if err != nil {
					got.Err = err.Error()
				}
			}
			got.ScannedPackages = scanner.scannedPackages
			got.CloseCalls = scanner.closeCalls
			got.CloseErrorLogged = strings.Contains(strings.Join(reporter.logs, ""), tc.CloseErr) && tc.CloseErr != ""

			if diff := cmp.Diff(tc.Expected, got); diff != "" {
				t.Errorf("scanAllPackagesForVulnerabilitiesWithScannerFactory() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

type fakeSBOMVulnerabilityScanner struct {
	scannedPackages []string
	scanErrPackage  string
	closeErr        string
	closeCalls      int
}

func (s *fakeSBOMVulnerabilityScanner) Scan(_ *buildContext, p *Package, _ string, _ string) (*PackageVulnerabilityStats, error) {
	s.scannedPackages = append(s.scannedPackages, p.FullName())
	if p.FullName() == s.scanErrPackage {
		return nil, errors.New("scan failure")
	}
	return &PackageVulnerabilityStats{Name: p.FullName()}, nil
}

func (s *fakeSBOMVulnerabilityScanner) Close() error {
	s.closeCalls++
	if s.closeErr != "" {
		return errors.New(s.closeErr)
	}
	return nil
}

type sbomScanTestCache map[string]string

func (c sbomScanTestCache) Location(pkg leewaycache.Package) (string, bool) {
	path, ok := c[pkg.FullName()]
	return path, ok
}

type sbomScanRecordingReporter struct {
	NoopReporter
	logs []string
}

func (r *sbomScanRecordingReporter) PackageBuildLog(_ *Package, _ bool, buf []byte) {
	r.logs = append(r.logs, string(buf))
}
