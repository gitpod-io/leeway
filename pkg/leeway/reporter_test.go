package leeway

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/gookit/color"
)

func TestConsoleReporter(t *testing.T) {
	t.Parallel()

	// Disable colors for consistent test output across environments.
	color.Enable = false

	type Expectation struct {
		Output string
	}

	start := time.Now()
	pkg := &Package{
		C: &Component{
			Name: "test",
		},
		PackageInternal: PackageInternal{
			Name: "test",
		},
	}

	tests := []struct {
		Name     string
		Reporter Reporter
		Func     func(t *testing.T, r *ConsoleReporter)
		Expect   Expectation
	}{
		{
			Name: "all phases",
			Func: func(t *testing.T, r *ConsoleReporter) {
				r.PackageBuildStarted(pkg, "/tmp/build")

				r.now = func() time.Time {
					return start.Add(6 * time.Second)
				}
				r.PackageBuildFinished(pkg, &PackageBuildReport{
					Phases: []PackageBuildPhase{
						PackageBuildPhasePrep,
						PackageBuildPhasePull,
						PackageBuildPhaseLint,
						PackageBuildPhaseTest,
						PackageBuildPhaseBuild,
						PackageBuildPhaseSBOM},
					phaseEnter: map[PackageBuildPhase]time.Time{
						PackageBuildPhasePrep:  start,
						PackageBuildPhasePull:  start.Add(time.Second),
						PackageBuildPhaseBuild: start.Add(2 * time.Second),
						PackageBuildPhaseTest:  start.Add(3 * time.Second),
						PackageBuildPhaseLint:  start.Add(4 * time.Second),
						PackageBuildPhaseSBOM:  start.Add(5 * time.Second),
					},
					phaseDone: map[PackageBuildPhase]time.Time{
						PackageBuildPhasePrep:  start.Add(time.Second),
						PackageBuildPhasePull:  start.Add(2 * time.Second),
						PackageBuildPhaseBuild: start.Add(3 * time.Second),
						PackageBuildPhaseTest:  start.Add(4 * time.Second),
						PackageBuildPhaseLint:  start.Add(5 * time.Second),
						PackageBuildPhaseSBOM:  start.Add(6 * time.Second),
					},
				})
			},
			Expect: Expectation{
				Output: `[test:test] build started (version unknown, builddir /tmp/build)
[test:test] package build succeeded in 6.00s (prep 1.0s, pull 1.0s, lint 1.0s, test 1.0s, build 1.0s, sbom 1.0s)
`,
			},
		},
		{
			Name: "no phases",
			Func: func(t *testing.T, r *ConsoleReporter) {
				r.PackageBuildStarted(pkg, "/tmp/build")
				r.PackageBuildFinished(pkg, &PackageBuildReport{
					Phases: []PackageBuildPhase{},
				})
			},
			Expect: Expectation{
				Output: `[test:test] build started (version unknown, builddir /tmp/build)
[test:test] package build succeeded in 0.00s
`,
			},
		},
		{
			Name: "failed build",
			Func: func(t *testing.T, r *ConsoleReporter) {
				r.PackageBuildStarted(pkg, "/tmp/build")
				r.PackageBuildFinished(pkg, &PackageBuildReport{
					Error: errors.New("failed"),
				})
			},
			Expect: Expectation{
				Output: `[test:test] build started (version unknown, builddir /tmp/build)
[test:test] package build failed while preping
[test:test] Reason: failed
`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			var (
				act Expectation
				buf bytes.Buffer
			)

			reporter := NewConsoleReporter()
			reporter.out = &buf
			reporter.now = func() time.Time {
				return start
			}

			test.Func(t, reporter)
			act.Output = buf.String()

			if diff := cmp.Diff(test.Expect.Output, act.Output); diff != "" {
				t.Errorf("output mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
