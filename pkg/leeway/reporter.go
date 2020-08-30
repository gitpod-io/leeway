package leeway

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/gookit/color"
	"github.com/segmentio/textio"
	log "github.com/sirupsen/logrus"
)

// Reporter provides feedback about the build progress to the user.
//
// Implementers beware: all these functions will be called in the hotpath of the build system.
//                      That means that blocking in those functions will block the actual build.
type Reporter interface {
	// BuildStarted is called when the build of a package is started by the user.
	// This is not the same as a dependency beeing built (see PackageBuildStarted for that).
	// The root package will also be passed into PackageBuildStarted once all its depepdencies
	// have been built.
	BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus)

	// BuildFinished is called when the build of a package whcih was started by the user has finished.
	// This is not the same as a dependency build finished (see PackageBuildFinished for that).
	// The root package will also be passed into PackageBuildFinished once it's been built.
	BuildFinished(pkg *Package, err error)

	// PackageBuildStarted is called when a package build actually gets underway. At this point
	// all transitive dependencies of the package have been built.
	PackageBuildStarted(pkg *Package)

	// PackageBuildLog is called during a package build whenever a build command produced some output.
	PackageBuildLog(pkg *Package, isErr bool, buf []byte)

	// PackageBuildFinished is called when the package build has finished. If an error is passed in
	// the package build was not succesfull.
	PackageBuildFinished(pkg *Package, err error)
}

// ConsoleReporter reports build progress by printing to stdout/stderr
type ConsoleReporter struct {
	opts   ConsoleReporterOpts
	writer map[string]io.Writer
	times  map[string]time.Time
	mu     sync.RWMutex
}

// exclusiveWriter makes a write an exclusive resource by protecting Write calls with a mutex.
type exclusiveWriter struct {
	O  io.Writer
	mu sync.Mutex
}

func (w *exclusiveWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.O.Write(p)
}

// ErrNoEstimate is returned by an DurationEstimator if there's not estimate available for a package
var ErrNoEstimate = fmt.Errorf("no estimate available")

// DurationEstimator estimates the build duration for a package.
// If total is true, this function will estimate the total build time, i.e. including all dependencies
// that require building.
// If total is false, this function will just estimate the build time for this particular package.
type DurationEstimator func(pkg *Package, total bool) (mostLikelyMS, n95Low, n95High int64, err error)

// ConsoleReporterOpts configures a console reporter
type ConsoleReporterOpts struct {
	DurationEstimator func(pkg *Package, total bool) (mostLikelyMS, n95Low, n95High int64, err error)
}

// NewConsoleReporter produces a new console logger
func NewConsoleReporter(opts ConsoleReporterOpts) *ConsoleReporter {
	return &ConsoleReporter{
		opts:   opts,
		writer: make(map[string]io.Writer),
		times:  make(map[string]time.Time),
	}
}

func (r *ConsoleReporter) getWriter(pkg *Package) io.Writer {
	name := pkg.FullName()

	r.mu.RLock()
	res, ok := r.writer[name]
	r.mu.RUnlock()

	if !ok {
		r.mu.Lock()
		res, ok = r.writer[name]
		if ok {
			// someone else was quicker in the meantime and created a new writer.
			r.mu.Unlock()
			return res
		}

		res = &exclusiveWriter{O: textio.NewPrefixWriter(os.Stdout, getRunPrefix(pkg))}
		r.writer[name] = res
		r.mu.Unlock()
	}

	return res
}

// BuildStarted is called when the build of a package is started by the user.
func (r *ConsoleReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {
	lines := make([]string, 0, len(status))
	if r.opts.DurationEstimator != nil {
		mostLikely, n95low, n95high, err := r.opts.DurationEstimator(pkg, true)
		if err != nil {
			log.WithError(err).Debug("cannot get build time estimate")
		}
		lines = append(lines, fmt.Sprintf("\tEst. build duration\t%d < %d < %d\n", n95low, mostLikely, n95high))
	}

	// now that the local cache is warm, we can print the list of work we have to do
	for pkg, status := range status {
		version, err := pkg.Version()
		if err != nil {
			version = "unknown"
		}

		format := "%s\t%s\t%s\n"
		if status == PackageBuilt {
			lines = append(lines, fmt.Sprintf(format, color.Green.Sprint("📦\tcached"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version)))
		} else {
			lines = append(lines, fmt.Sprintf(format, color.Yellow.Sprint("🔧\tbuild"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version)))
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i] < lines[j] })
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(lines, ""))
	tw.Flush()
}

// BuildFinished is called when the build of a package whcih was started by the user has finished.
func (r *ConsoleReporter) BuildFinished(pkg *Package, err error) {
	if err != nil {
		color.Printf("<red>build failed</>\n<white>Reason:</> %s\n", err)
		return
	}

	color.Println("\n<green>build succeded</>")
}

// PackageBuildStarted is called when a package build actually gets underway.
func (r *ConsoleReporter) PackageBuildStarted(pkg *Package) {
	out := r.getWriter(pkg)

	version, err := pkg.Version()
	if err != nil {
		version = "unknown"
	}

	r.mu.Lock()
	r.times[pkg.FullName()] = time.Now()
	r.mu.Unlock()

	io.WriteString(out, color.Sprintf("<fg=yellow>build started</> <gray>(version %s)</>\n", version))
	if r.opts.DurationEstimator != nil {
		mostLikely, n95low, n95high, err := r.opts.DurationEstimator(pkg, false)
		if err != nil {
			log.WithError(err).Debug("cannot get build time estimate")
		}

		var (
			tML   = time.Duration(mostLikely) * time.Millisecond
			tN98L = time.Duration(n95low) * time.Millisecond
			tN98H = time.Duration(n95high) * time.Millisecond
		)
		io.WriteString(out, color.Sprintf("              <gray>est. build duration\t%s < %s < %s</>\n", tN98L.String(), tML.String(), tN98H.String()))
	}
}

// PackageBuildLog is called during a package build whenever a build command produced some output.
func (r *ConsoleReporter) PackageBuildLog(pkg *Package, isErr bool, buf []byte) {
	out := r.getWriter(pkg)
	out.Write(buf)
}

// PackageBuildFinished is called when the package build has finished.
func (r *ConsoleReporter) PackageBuildFinished(pkg *Package, err error) {
	nme := pkg.FullName()
	out := r.getWriter(pkg)

	r.mu.Lock()
	dur := time.Since(r.times[nme])
	delete(r.writer, nme)
	delete(r.times, nme)
	r.mu.Unlock()

	msg := color.Sprintf("<green>package build succeded</> <gray>(%.2fs)</>\n", dur.Seconds())
	if err != nil {
		msg = color.Sprintf("<red>package build failed</>\n<white>Reason:</> %s\n", err)
	}
	io.WriteString(out, msg)
}

func getRunPrefix(p *Package) string {
	return color.Gray.Render(fmt.Sprintf("[%s] ", p.FullName()))
}

// NewWerftReporter craetes a new werft compatible reporter
func NewWerftReporter(opts ConsoleReporterOpts) *WerftReporter {
	return &WerftReporter{
		ConsoleReporter: NewConsoleReporter(ConsoleReporterOpts{}),
	}
}

// WerftReporter works like the console reporter but adds werft output
type WerftReporter struct {
	*ConsoleReporter
}

// BuildStarted is called when the build of a package is started by the user.
func (r *WerftReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {
	r.ConsoleReporter.BuildStarted(pkg, status)

	for p, s := range status {
		if s != PackageNotBuiltYet {
			continue
		}
		if p.Ephemeral {
			continue
		}

		// TODO(cw): use estimator to collect build time estimates for all packages
		fmt.Printf("[%s|START] will be built\n", p.FullName())
	}
}

// PackageBuildFinished is called when the package build has finished.
func (r *WerftReporter) PackageBuildFinished(pkg *Package, err error) {
	r.ConsoleReporter.PackageBuildFinished(pkg, err)

	if cfg, ok := pkg.Config.(DockerPkgConfig); ok && pkg.Type == DockerPackage {
		for _, img := range cfg.Image {
			fmt.Printf("[docker|RESULT] %s\n", img)
		}
	}

	var (
		status string
		msg    string
	)
	if err == nil {
		status = "DONE"
		msg = "build succeeded"
	} else {
		status = "FAIL"
		msg = err.Error()
	}
	fmt.Printf("[%s|%s] %s\n", pkg.FullName(), status, msg)
}
