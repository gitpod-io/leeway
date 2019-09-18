package leeway

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

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
	writer map[string]io.Writer
	mu     sync.RWMutex
}

// NewConsoleReporter produces a new console logger
func NewConsoleReporter() *ConsoleReporter {
	return &ConsoleReporter{
		writer: make(map[string]io.Writer),
	}
}

// BuildStarted is called when the build of a package is started by the user.
func (r *ConsoleReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {
	// now that the local cache is warm, we can print the list of work we have to do
	lines := make([]string, len(status))
	i := 0
	for pkg, status := range status {
		format := "%s\t%s\n"
		if status == PackageBuilt {
			lines[i] = fmt.Sprintf(format, color.Green.Sprint("📦\tcached"), pkg.FullName())
		} else {
			lines[i] = fmt.Sprintf(format, color.Yellow.Sprint("🔧\tbuild"), pkg.FullName())
		}
		i++
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
	nme := pkg.FullName()

	out := textio.NewPrefixWriter(os.Stdout, getRunPrefix(pkg))

	r.mu.Lock()
	r.writer[nme] = out
	r.mu.Unlock()

	io.WriteString(out, color.Yellow.Render("build started\n"))
}

// PackageBuildLog is called during a package build whenever a build command produced some output.
func (r *ConsoleReporter) PackageBuildLog(pkg *Package, isErr bool, buf []byte) {
	nme := pkg.FullName()

	r.mu.RLock()
	out, ok := r.writer[nme]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		out = textio.NewPrefixWriter(os.Stdout, getRunPrefix(pkg))
		r.writer[nme] = out
		log.WithField("package", nme).Debug("saw build log output before the build started")
		r.mu.Unlock()
	}

	out.Write(buf)
}

// PackageBuildFinished is called when the package build has finished.
func (r *ConsoleReporter) PackageBuildFinished(pkg *Package, err error) {
	msg := color.Render("<green>package build succeded</>")
	if err != nil {
		msg = color.Sprintf("<red>package build failed</>\n<white>Reason:</> %s\n", err)
	}

	nme := pkg.FullName()
	r.mu.RLock()
	out, ok := r.writer[nme]
	r.mu.RUnlock()

	if !ok {
		out = textio.NewPrefixWriter(os.Stdout, getRunPrefix(pkg))
	}

	io.WriteString(out, msg)

	delete(r.writer, nme)
}

func getRunPrefix(p *Package) string {
	return color.Gray.Render(fmt.Sprintf("[%s] ", p.FullName()))
}
