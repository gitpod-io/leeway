package leeway

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gookit/color"
	"github.com/segmentio/textio"
)

// Reporter provides feedback about the build progress to the user.
//
// Implementers beware: all these functions will be called in the hotpath of the build system. That means that blocking in those functions will block the actual build.
type Reporter interface {
	// BuildStarted is called when the build of a package is started by the user.
	// This is not the same as a dependency beeing built (see PackageBuildStarted for that).
	// The root package will also be passed into PackageBuildStarted once all its depepdencies
	// have been built.
	BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus)

	// BuildFinished is called when the build of a package which was started by the user has finished.
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

// NewConsoleReporter produces a new console logger
func NewConsoleReporter() *ConsoleReporter {
	return &ConsoleReporter{
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
	// now that the local cache is warm, we can print the list of work we have to do
	lines := make([]string, len(status))
	i := 0
	for pkg, status := range status {
		version, err := pkg.Version()
		if err != nil {
			version = "unknown"
		}

		format := "%s\t%s\t%s\n"
		if status == PackageBuilt {
			lines[i] = fmt.Sprintf(format, color.Green.Sprint("📦\tcached locally"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		} else if status == PackageInRemoteCache {
			lines[i] = fmt.Sprintf(format, color.Green.Sprint("🌎\tcached remotely (ignored)"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		} else if status == PackageDownloaded {
			lines[i] = fmt.Sprintf(format, color.Green.Sprint("📥\tcached remotely (downloaded)"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		} else {
			lines[i] = fmt.Sprintf(format, color.Yellow.Sprint("🔧\tbuild"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		}
		i++
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i] < lines[j] })
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(lines, ""))
	tw.Flush()
}

// BuildFinished is called when the build of a package which was started by the user has finished.
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

	_, _ = io.WriteString(out, color.Sprintf("<fg=yellow>build started</> <gray>(version %s)</>\n", version))
}

// PackageBuildLog is called during a package build whenever a build command produced some output.
func (r *ConsoleReporter) PackageBuildLog(pkg *Package, isErr bool, buf []byte) {
	out := r.getWriter(pkg)
	//nolint:errcheck
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
	//nolint:errcheck
	io.WriteString(out, msg)
}

func getRunPrefix(p *Package) string {
	return color.Gray.Render(fmt.Sprintf("[%s] ", p.FullName()))
}

// NewWerftReporter craetes a new werft compatible reporter
func NewWerftReporter() *WerftReporter {
	return &WerftReporter{
		ConsoleReporter: NewConsoleReporter(),
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

type PackageReport struct {
	logs     strings.Builder
	start    time.Time
	duration time.Duration
	status   PackageBuildStatus
	results  []string
	err      error
}

func (r *PackageReport) StatusIcon() string {
	if r.HasError() {
		return "❌"
	}
	switch r.status {
	case PackageBuilt:
		return "✅"
	case PackageBuilding:
		return "🏃"
	case PackageInRemoteCache:
		return "🌎"
	case PackageDownloaded:
		return "📥"
	case PackageNotBuiltYet:
		return "🔧"
	default:
		return "?"
	}
}

func (r *PackageReport) DurationInSeconds() string {
	return fmt.Sprintf("%.2fs", r.duration.Seconds())
}

func (r *PackageReport) HasLogs() bool {
	return r.logs.Len() > 0
}

func (r *PackageReport) Logs() string {
	return strings.TrimSpace(r.logs.String())
}

func (r *PackageReport) HasResults() bool {
	return len(r.results) > 0
}

func (r *PackageReport) Results() []string {
	return r.results
}

func (r *PackageReport) HasError() bool {
	return r.err != nil
}

func (r *PackageReport) Error() string {
	return fmt.Sprintf("%s", r.err)
}

type HTMLReporter struct {
	delegate    Reporter
	filename    string
	reports     map[string]*PackageReport
	rootPackage *Package
	mu          sync.RWMutex
}

func NewHTMLReporter(del Reporter, filename string) *HTMLReporter {
	return &HTMLReporter{
		delegate: del,
		filename: filename,
		reports:  make(map[string]*PackageReport),
	}
}

func (r *HTMLReporter) getReport(pkg *Package) *PackageReport {
	name := pkg.FullName()

	r.mu.RLock()
	rep, ok := r.reports[name]
	r.mu.RUnlock()

	if !ok {
		r.mu.Lock()
		rep, ok = r.reports[name]
		if ok {
			r.mu.Unlock()
			return rep
		}

		rep = &PackageReport{status: PackageNotBuiltYet}
		r.reports[name] = rep
		r.mu.Unlock()
	}

	return rep
}

func (r *HTMLReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {
	r.rootPackage = pkg
	r.delegate.BuildStarted(pkg, status)
}

func (r *HTMLReporter) BuildFinished(pkg *Package, err error) {
	r.delegate.BuildFinished(pkg, err)
	r.Report()
}

func (r *HTMLReporter) PackageBuildStarted(pkg *Package) {
	r.delegate.PackageBuildStarted(pkg)
	rep := r.getReport(pkg)
	rep.start = time.Now()
	rep.status = PackageBuilding
}

func (r *HTMLReporter) PackageBuildLog(pkg *Package, isErr bool, buf []byte) {
	report := r.getReport(pkg)
	report.logs.Write(buf)
	r.delegate.PackageBuildLog(pkg, isErr, buf)
}

func (r *HTMLReporter) PackageBuildFinished(pkg *Package, err error) {
	r.delegate.PackageBuildFinished(pkg, err)
	rep := r.getReport(pkg)
	rep.duration = time.Since(rep.start)
	rep.status = PackageBuilt
	rep.err = err

	if cfg, ok := pkg.Config.(DockerPkgConfig); ok && pkg.Type == DockerPackage {
		rep.results = cfg.Image
	}
}

func (r *HTMLReporter) Report() {
	vars := make(map[string]interface{})
	vars["Name"] = r.filename
	vars["Packages"] = r.reports
	vars["RootPackage"] = r.rootPackage

	tmplString := `
<h1>{{ .RootPackage.FullName }}</h1>
<p>Leeway built the following packages</p>
<table>
	<thead>
		<tr>
			<td>🚦 Status</td>
			<td>📦 Package</td>
			<td>⏰ Duration</td>
			<td>🔬 Details</td>
		</tr>
	</thread>
	<tbody>
		{{- range $pkg, $report := .Packages }}
		<tr>
			<td>{{ $report.StatusIcon }}</td>
			<td>{{ $pkg }}</td>
			<td>{{ $report.DurationInSeconds -}}</td>
			<td><a href="#{{ $pkg }}">See below</td>
		</tr>
		{{- end }}
	</tbody>
<table>
<p>For details around each package, see below<p>
{{- range $pkg, $report := .Packages }}
<h2 id="{{ $pkg }}">{{ $pkg }}</h2>
{{ if $report.HasError -}}
<details open> 
	<summary>Error message</summary>
	<pre><code>{{ $report.Error }}</code></pre>
</details>
{{ end -}}
{{ if $report.HasResults -}}
<details>
	<summary>Results</summary>
	<ul>
	{{- range $result := $report.Results }}
		<li><code>{{ $result }}</code></li>
	{{ end -}}
	</ul>
</details>
{{ end -}}
<details>
	<summary>Logs</summary>
	{{ if $report.HasLogs -}}
	<pre><code>{{ $report.Logs }}</code></pre>
	{{- else -}}
	<pre>No logs</pre>
	{{- end }}
</details>
{{- end -}}
`
	tmpl, _ := template.New("Report").Parse(strings.ReplaceAll(tmplString, "'", "`"))

	file, _ := os.Create(r.filename)
	defer file.Close()

	err := tmpl.Execute(file, vars)
	if err != nil {
		log.WithError(err).Fatal("Can't render template")
	}
}
