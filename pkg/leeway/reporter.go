package leeway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"text/template"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/gookit/color"
	segment "github.com/segmentio/analytics-go/v3"
	"github.com/segmentio/textio"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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
	PackageBuildStarted(pkg *Package, builddir string)

	// PackageBuildLog is called during a package build whenever a build command produced some output.
	PackageBuildLog(pkg *Package, isErr bool, buf []byte)

	// PackageBuildFinished is called when the package build has finished. If an error is passed in
	// the package build was not succesfull.
	PackageBuildFinished(pkg *Package, rep *PackageBuildReport)
}

// TestTracingReporter is an optional interface that reporters can implement
// to support creating spans for individual Go tests during the test phase.
type TestTracingReporter interface {
	Reporter

	// GetGoTestTracer returns a GoTestTracer for creating test spans as children
	// of the package's test phase span. Returns nil if test tracing is not available.
	GetGoTestTracer(pkg *Package) *GoTestTracer
}

type PackageBuildReport struct {
	phaseEnter map[PackageBuildPhase]time.Time
	phaseDone  map[PackageBuildPhase]time.Time

	Phases []PackageBuildPhase
	Error  error

	TestCoverageAvailable  bool
	TestCoveragePercentage int
	FunctionsWithoutTest   int
	FunctionsWithTest      int
}

// PhaseDuration returns the time it took to execute the phases commands
func (rep *PackageBuildReport) PhaseDuration(phase PackageBuildPhase) (dt time.Duration) {
	enter, eok := rep.phaseEnter[phase]
	done, dok := rep.phaseDone[phase]

	if !eok {
		return 0
	}
	if eok && !dok {
		return -1
	}
	return done.Sub(enter)
}

// LastPhase returns the phase the package build last entered
func (rep *PackageBuildReport) LastPhase() PackageBuildPhase {
	if len(rep.Phases) == 0 {
		return PackageBuildPhasePrep
	}
	return rep.Phases[len(rep.Phases)-1]
}

// TotalTime is the total time spent on building this package
func (rep *PackageBuildReport) TotalTime() time.Duration {
	enter := rep.phaseEnter[PackageBuildPhasePrep]
	done := rep.phaseDone[rep.LastPhase()]
	return done.Sub(enter)
}

// ConsoleReporter reports build progress by printing to stdout/stderr
type ConsoleReporter struct {
	writer map[string]io.Writer
	times  map[string]time.Time
	mu     sync.RWMutex

	// out is the writer to print to. Normally this is os.Stdout, but it can be set to a buffer for testing.
	out io.Writer
	now func() time.Time
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
		out:    os.Stdout,
		now:    time.Now,
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

		res = &exclusiveWriter{O: textio.NewPrefixWriter(r.out, getRunPrefix(pkg))}
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
		switch status {
		case PackageBuilt:
			lines[i] = fmt.Sprintf(format, color.Green.Sprint("📦\tcached locally"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		case PackageInRemoteCache:
			lines[i] = fmt.Sprintf(format, color.Green.Sprint("🌎\tcached remotely (available)"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		case PackageDownloaded:
			lines[i] = fmt.Sprintf(format, color.Green.Sprint("📥\tcached remotely (downloaded)"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		case PackageVerificationFailed:
			lines[i] = fmt.Sprintf(format, color.Yellow.Sprint("⚠️\tverification failed (will rebuild)"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		case PackageDownloadFailed:
			lines[i] = fmt.Sprintf(format, color.Yellow.Sprint("⚠️\tdownload failed (will rebuild)"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		default:
			lines[i] = fmt.Sprintf(format, color.Yellow.Sprint("🔧\tbuild"), pkg.FullName(), color.Gray.Sprintf("(version %s)", version))
		}
		i++
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i] < lines[j] })
	tw := tabwriter.NewWriter(r.out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(lines, ""))
	tw.Flush()
}

// BuildFinished is called when the build of a package which was started by the user has finished.
func (r *ConsoleReporter) BuildFinished(pkg *Package, err error) {
	if err != nil {
		color.Printf("<red>build failed</>\n<white>Reason:</> %s\n", err)
		return
	}

	color.Println("\n<green>build succeeded</>")
}

// PackageBuildStarted is called when a package build actually gets underway.
func (r *ConsoleReporter) PackageBuildStarted(pkg *Package, builddir string) {
	out := r.getWriter(pkg)

	version, err := pkg.Version()
	if err != nil {
		version = "unknown"
	}

	r.mu.Lock()
	r.times[pkg.FullName()] = r.now()
	r.mu.Unlock()

	_, _ = io.WriteString(out, color.Sprintf("<fg=yellow>build started</> <gray>(version %s, builddir %s)</>\n", version, builddir))
}

// PackageBuildLog is called during a package build whenever a build command produced some output.
func (r *ConsoleReporter) PackageBuildLog(pkg *Package, isErr bool, buf []byte) {
	out := r.getWriter(pkg)
	//nolint:errcheck
	out.Write(buf)
}

// PackageBuildFinished is called when the package build has finished.
func (r *ConsoleReporter) PackageBuildFinished(pkg *Package, rep *PackageBuildReport) {
	nme := pkg.FullName()
	out := r.getWriter(pkg)

	r.mu.Lock()
	dur := r.now().Sub(r.times[nme])
	delete(r.writer, nme)
	delete(r.times, nme)
	r.mu.Unlock()

	// Format phase durations
	var phaseDurations []string
	for _, phase := range rep.Phases {
		if d := rep.PhaseDuration(phase); d > 0 {
			phaseDurations = append(phaseDurations, fmt.Sprintf("%s %.1fs", phase, d.Seconds()))
		}
	}
	phaseDurStr := ""
	if len(phaseDurations) > 0 {
		phaseDurStr = color.Sprintf(" (%s)", strings.Join(phaseDurations, ", "))
	}

	var msg string
	if rep.Error != nil {
		msg = color.Sprintf("<red>package build failed while %sing</>\n<white>Reason:</> %s\n", rep.LastPhase(), rep.Error)
	} else {
		var coverage string
		if rep.TestCoverageAvailable {
			coverage = color.Sprintf("<fg=yellow>test coverage: %d%%</> <gray>(%d of %d functions have tests)</>\n", rep.TestCoveragePercentage, rep.FunctionsWithTest, rep.FunctionsWithTest+rep.FunctionsWithoutTest)
		}
		msg = color.Sprintf("%s<green>package build succeeded</> <gray>in %.2fs%s</>\n", coverage, dur.Seconds(), phaseDurStr)
	}
	//nolint:errcheck
	io.WriteString(out, msg)
}

func getRunPrefix(p *Package) string {
	return color.Gray.Render(fmt.Sprintf("[%s] ", p.FullName()))
}

// NewWerftReporter craetes a new werft compatible reporter
func NewWerftReporter() *WerftReporter {
	return &WerftReporter{}
}

// WerftReporter works like the console reporter but adds werft output
type WerftReporter struct {
	NoopReporter
}

// BuildStarted is called when the build of a package is started by the user.
func (r *WerftReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {
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
func (r *WerftReporter) PackageBuildFinished(pkg *Package, rep *PackageBuildReport) {
	if cfg, ok := pkg.Config.(DockerPkgConfig); ok && pkg.Type == DockerPackage {
		for _, img := range cfg.Image {
			fmt.Printf("[docker|RESULT] %s\n", img)
		}
	}

	var (
		status string
		msg    string
	)
	if rep.Error == nil {
		status = "DONE"
		msg = "build succeeded"
	} else {
		status = "FAIL"
		msg = rep.Error.Error()
	}
	fmt.Printf("[%s|%s] %s\n", pkg.FullName(), status, msg)
}

type HTMLPackageReport struct {
	ID       string
	logs     strings.Builder
	start    time.Time
	duration time.Duration
	status   PackageBuildStatus
	results  []string
	err      error
}

func (r *HTMLPackageReport) StatusIcon() string {
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

func (r *HTMLPackageReport) DurationInSeconds() string {
	return fmt.Sprintf("%.2fs", r.duration.Seconds())
}

func (r *HTMLPackageReport) HasLogs() bool {
	return r.logs.Len() > 0
}

func (r *HTMLPackageReport) Logs() string {
	return strings.TrimSpace(r.logs.String())
}

func (r *HTMLPackageReport) HasResults() bool {
	return len(r.results) > 0
}

func (r *HTMLPackageReport) Results() []string {
	return r.results
}

func (r *HTMLPackageReport) HasError() bool {
	return r.err != nil
}

func (r *HTMLPackageReport) Error() string {
	return fmt.Sprintf("%s", r.err)
}

type HTMLReporter struct {
	filename    string
	reports     map[string]*HTMLPackageReport
	rootPackage *Package
	mu          sync.RWMutex
}

func NewHTMLReporter(filename string) *HTMLReporter {
	return &HTMLReporter{
		filename: filename,
		reports:  make(map[string]*HTMLPackageReport),
	}
}

func (r *HTMLReporter) getReport(pkg *Package) *HTMLPackageReport {
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

		rep = &HTMLPackageReport{
			ID:     pkg.FilesystemSafeName(),
			status: PackageNotBuiltYet,
		}
		r.reports[name] = rep
		r.mu.Unlock()
	}

	return rep
}

func (r *HTMLReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {
	r.rootPackage = pkg
}

func (r *HTMLReporter) BuildFinished(pkg *Package, err error) {
	r.Report()
}

func (r *HTMLReporter) PackageBuildStarted(pkg *Package, builddir string) {
	rep := r.getReport(pkg)
	rep.start = time.Now()
	rep.status = PackageBuilding
}

func (r *HTMLReporter) PackageBuildLog(pkg *Package, isErr bool, buf []byte) {
	report := r.getReport(pkg)
	report.logs.Write(buf)
}

func (r *HTMLReporter) PackageBuildFinished(pkg *Package, rep *PackageBuildReport) {
	hrep := r.getReport(pkg)
	hrep.duration = time.Since(hrep.start)
	hrep.status = PackageBuilt
	hrep.err = rep.Error

	if cfg, ok := pkg.Config.(DockerPkgConfig); ok && pkg.Type == DockerPackage {
		hrep.results = cfg.Image
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
			<td><a href="#{{ $report.ID }}">See below</td>
		</tr>
		{{- end }}
	</tbody>
<table>
<p>For details about each package, see below<p>
{{- range $pkg, $report := .Packages }}
<h2 id="{{ $report.ID }}">{{ $report.StatusIcon }} {{ $pkg }}</h2>
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

	file, err := os.Create(r.filename)
	if err != nil {
		log.WithError(err).WithField("filename", r.filename).Fatal("Failed to create output file")
		return
	}
	defer file.Close()

	err = tmpl.Execute(file, vars)
	if err != nil {
		log.WithError(err).Fatal("Can't render template")
	}
}

type CompositeReporter []Reporter

// BuildFinished implements Reporter
func (cr CompositeReporter) BuildFinished(pkg *Package, err error) {
	for _, r := range cr {
		r.BuildFinished(pkg, err)
	}
}

// BuildStarted implements Reporter
func (cr CompositeReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {
	for _, r := range cr {
		r.BuildStarted(pkg, status)
	}
}

// PackageBuildFinished implements Reporter
func (cr CompositeReporter) PackageBuildFinished(pkg *Package, rep *PackageBuildReport) {
	for _, r := range cr {
		r.PackageBuildFinished(pkg, rep)
	}
}

// PackageBuildLog implements Reporter
func (cr CompositeReporter) PackageBuildLog(pkg *Package, isErr bool, buf []byte) {
	for _, r := range cr {
		r.PackageBuildLog(pkg, isErr, buf)
	}
}

// PackageBuildStarted implements Reporter
func (cr CompositeReporter) PackageBuildStarted(pkg *Package, builddir string) {
	for _, r := range cr {
		r.PackageBuildStarted(pkg, builddir)
	}
}

// GetGoTestTracer implements TestTracingReporter by delegating to the first
// wrapped reporter that supports test tracing.
func (cr CompositeReporter) GetGoTestTracer(pkg *Package) *GoTestTracer {
	for _, r := range cr {
		if tr, ok := r.(TestTracingReporter); ok {
			if tracer := tr.GetGoTestTracer(pkg); tracer != nil {
				return tracer
			}
		}
	}
	return nil
}

var _ Reporter = CompositeReporter{}
var _ TestTracingReporter = CompositeReporter{}

type NoopReporter struct{}

// BuildFinished implements Reporter
func (*NoopReporter) BuildFinished(pkg *Package, err error) {}

// BuildStarted implements Reporter
func (*NoopReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {}

// PackageBuildFinished implements Reporter
func (*NoopReporter) PackageBuildFinished(pkg *Package, rep *PackageBuildReport) {}

// PackageBuildLog implements Reporter
func (*NoopReporter) PackageBuildLog(pkg *Package, isErr bool, buf []byte) {}

// PackageBuildStarted implements Reporter
func (*NoopReporter) PackageBuildStarted(pkg *Package, builddir string) {}

var _ Reporter = ((*NoopReporter)(nil))

func NewSegmentReporter(key string) *SegmentReporter {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Errorf("cannot produce segment reporter anonymous ID: %w", err))
	}
	return &SegmentReporter{
		AnonymousId: id.String(),
		key:         key,
	}
}

type SegmentReporter struct {
	NoopReporter

	AnonymousId string
	key         string

	client segment.Client
	mu     sync.Mutex
}

// BuildStarted implements Reporter
func (sr *SegmentReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {
	sr.mu.Lock()
	sr.client = segment.New(sr.key)
	sr.mu.Unlock()

	props := make(segment.Properties)
	addPackageToSegmentEventProps(props, pkg)
	sr.track("build_started", props)
}

func (sr *SegmentReporter) BuildFinished(pkg *Package, err error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	props := segment.Properties{
		"success": err == nil,
	}
	addPackageToSegmentEventProps(props, pkg)
	sr.track("build_finished", props)

	sr.client.Close()
	sr.client = nil
}

func (sr *SegmentReporter) PackageBuildFinished(pkg *Package, rep *PackageBuildReport) {
	props := segment.Properties{
		"success":    rep.Error == nil,
		"lastPhase":  rep.LastPhase(),
		"durationMS": rep.TotalTime().Milliseconds(),
	}
	if rep.TestCoverageAvailable {
		props["testCoverage"] = rep.TestCoveragePercentage
		props["functionsWithoutTest"] = rep.FunctionsWithoutTest
		props["functionsWithTest"] = rep.FunctionsWithTest
	}
	addPackageToSegmentEventProps(props, pkg)
	sr.track("package_build_finished", props)
}

func addPackageToSegmentEventProps(props segment.Properties, pkg *Package) {
	props["name"] = pkg.FullName()
	props["repo"] = pkg.C.W.Git.Origin
	props["dirtyWorkingCopy"] = pkg.C.W.Git.DirtyFiles(pkg.Sources)
	props["commit"] = pkg.C.W.Git.Commit
}

func (sr *SegmentReporter) track(event string, props segment.Properties) {
	evt := segment.Track{
		AnonymousId: sr.AnonymousId,
		Event:       event,
		Timestamp:   time.Now(),
		Context: &segment.Context{
			App: segment.AppInfo{Name: "leeway", Version: Version},
			OS:  segment.OSInfo{Name: runtime.GOOS},
		},
		Properties: props,
	}
	if sr.client == nil {
		log.WithField("event", evt).Warn("tried to report progress segment, but did not have a client")
		return
	}

	err := sr.client.Enqueue(evt)
	if err != nil {
		log.WithError(err).Warn("cannot report build progress to segment")
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		fc, _ := json.Marshal(evt)
		log.WithField("evt", string(fc)).Debug("reported segment event")
	}
}

func NewGitHubReporter() *GitHubActionReporter {
	return &GitHubActionReporter{}
}

type GitHubActionReporter struct {
	NoopReporter

	mu sync.Mutex
}

func (sr *GitHubActionReporter) PackageBuildFinished(pkg *Package, rep *PackageBuildReport) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	fn, ok := os.LookupEnv("GITHUB_OUTPUT")
	if !ok || fn == "" {
		return
	}
	f, err := os.OpenFile(fn, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.WithField("fn", fn).WithError(err).Warn("cannot open GITHUB_OUTPUT file")
		return
	}
	defer f.Close()

	var success bool
	if rep.Error == nil {
		success = true
	}
	fmt.Fprintf(f, "%s=%v\n", pkg.FilesystemSafeName(), success)
}

// OTelReporter reports build progress using OpenTelemetry tracing
type OTelReporter struct {
	NoopReporter

	tracer       trace.Tracer
	parentCtx    context.Context
	rootCtx      context.Context
	rootSpan     trace.Span
	packageCtxs  map[string]context.Context
	packageSpans map[string]trace.Span
	mu           sync.RWMutex
}

// NewOTelReporter creates a new OpenTelemetry reporter with the given tracer and parent context
func NewOTelReporter(tracer trace.Tracer, parentCtx context.Context) *OTelReporter {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	return &OTelReporter{
		tracer:       tracer,
		parentCtx:    parentCtx,
		packageCtxs:  make(map[string]context.Context),
		packageSpans: make(map[string]trace.Span),
	}
}

// BuildStarted implements Reporter
func (r *OTelReporter) BuildStarted(pkg *Package, status map[*Package]PackageBuildStatus) {
	if r.tracer == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Create root span for the build
	ctx, span := r.tracer.Start(r.parentCtx, "leeway.build",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	r.rootCtx = ctx
	r.rootSpan = span

	// Add root span attributes
	version, err := pkg.Version()
	if err != nil {
		version = "unknown"
	}

	span.SetAttributes(
		attribute.String("leeway.version", Version),
		attribute.String("leeway.workspace.root", pkg.C.W.Origin),
		attribute.String("leeway.target.package", pkg.FullName()),
		attribute.String("leeway.target.version", version),
	)

	// Add GitHub context attributes if available
	r.addGitHubAttributes(span)

	// Add build status summary
	var (
		cached   int
		remote   int
		download int
		toBuild  int
	)
	for _, s := range status {
		switch s {
		case PackageBuilt:
			cached++
		case PackageInRemoteCache:
			remote++
		case PackageDownloaded:
			download++
		case PackageNotBuiltYet:
			toBuild++
		}
	}

	span.SetAttributes(
		attribute.Int("leeway.packages.total", len(status)),
		attribute.Int("leeway.packages.cached", cached),
		attribute.Int("leeway.packages.remote", remote),
		attribute.Int("leeway.packages.downloaded", download),
		attribute.Int("leeway.packages.to_build", toBuild),
	)
}

// BuildFinished implements Reporter
func (r *OTelReporter) BuildFinished(pkg *Package, err error) {
	if r.tracer == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.rootSpan == nil {
		return
	}

	// Set error status if build failed
	if err != nil {
		r.rootSpan.RecordError(err)
		r.rootSpan.SetStatus(codes.Error, err.Error())
	} else {
		r.rootSpan.SetStatus(codes.Ok, "build completed successfully")
	}

	// End root span
	r.rootSpan.End()
	r.rootSpan = nil
	r.rootCtx = nil
}

// PackageBuildStarted implements Reporter
func (r *OTelReporter) PackageBuildStarted(pkg *Package, builddir string) {
	if r.tracer == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.rootCtx == nil {
		log.Warn("PackageBuildStarted called before BuildStarted")
		return
	}

	pkgName := pkg.FullName()

	// Create package span as child of root span
	ctx, span := r.tracer.Start(r.rootCtx, "leeway.package",
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	// Add package attributes
	version, err := pkg.Version()
	if err != nil {
		version = "unknown"
	}

	span.SetAttributes(
		attribute.String("leeway.package.name", pkgName),
		attribute.String("leeway.package.type", string(pkg.Type)),
		attribute.String("leeway.package.version", version),
		attribute.String("leeway.package.builddir", builddir),
	)

	// Store context and span
	r.packageCtxs[pkgName] = ctx
	r.packageSpans[pkgName] = span
}

// PackageBuildFinished implements Reporter
func (r *OTelReporter) PackageBuildFinished(pkg *Package, rep *PackageBuildReport) {
	if r.tracer == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	pkgName := pkg.FullName()
	span, ok := r.packageSpans[pkgName]
	if !ok {
		log.WithField("package", pkgName).Warn("PackageBuildFinished called without corresponding PackageBuildStarted")
		return
	}

	// Add build report attributes
	span.SetAttributes(
		attribute.String("leeway.package.last_phase", string(rep.LastPhase())),
		attribute.Int64("leeway.package.duration_ms", rep.TotalTime().Milliseconds()),
	)

	// Add phase durations
	for _, phase := range rep.Phases {
		duration := rep.PhaseDuration(phase)
		if duration >= 0 {
			span.SetAttributes(
				attribute.Int64(fmt.Sprintf("leeway.package.phase.%s.duration_ms", phase), duration.Milliseconds()),
			)
		}
	}

	// Add test coverage if available
	if rep.TestCoverageAvailable {
		span.SetAttributes(
			attribute.Int("leeway.package.test.coverage_percentage", rep.TestCoveragePercentage),
			attribute.Int("leeway.package.test.functions_with_test", rep.FunctionsWithTest),
			attribute.Int("leeway.package.test.functions_without_test", rep.FunctionsWithoutTest),
		)
	}

	// Set error status if build failed
	if rep.Error != nil {
		span.RecordError(rep.Error)
		span.SetStatus(codes.Error, rep.Error.Error())
	} else {
		span.SetStatus(codes.Ok, "package built successfully")
	}

	// End span
	span.End()

	// Clean up
	delete(r.packageSpans, pkgName)
	delete(r.packageCtxs, pkgName)
}

// addGitHubAttributes adds GitHub Actions context attributes to the span
func (r *OTelReporter) addGitHubAttributes(span trace.Span) {
	// Check if running in GitHub Actions
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return
	}

	// Add GitHub context attributes
	if val := os.Getenv("GITHUB_WORKFLOW"); val != "" {
		span.SetAttributes(attribute.String("github.workflow", val))
	}
	if val := os.Getenv("GITHUB_RUN_ID"); val != "" {
		span.SetAttributes(attribute.String("github.run_id", val))
	}
	if val := os.Getenv("GITHUB_RUN_NUMBER"); val != "" {
		span.SetAttributes(attribute.String("github.run_number", val))
	}
	if val := os.Getenv("GITHUB_JOB"); val != "" {
		span.SetAttributes(attribute.String("github.job", val))
	}
	if val := os.Getenv("GITHUB_ACTOR"); val != "" {
		span.SetAttributes(attribute.String("github.actor", val))
	}
	if val := os.Getenv("GITHUB_REPOSITORY"); val != "" {
		span.SetAttributes(attribute.String("github.repository", val))
	}
	if val := os.Getenv("GITHUB_REF"); val != "" {
		span.SetAttributes(attribute.String("github.ref", val))
	}
	if val := os.Getenv("GITHUB_SHA"); val != "" {
		span.SetAttributes(attribute.String("github.sha", val))
	}
	if val := os.Getenv("GITHUB_SERVER_URL"); val != "" {
		span.SetAttributes(attribute.String("github.server_url", val))
	}
	if val := os.Getenv("GITHUB_WORKFLOW_REF"); val != "" {
		span.SetAttributes(attribute.String("github.workflow_ref", val))
	}
}

// GetGoTestTracer returns a GoTestTracer for creating test spans as children
// of the package's span. This allows individual Go tests to be traced.
func (r *OTelReporter) GetGoTestTracer(pkg *Package) *GoTestTracer {
	if r.tracer == nil {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	pkgName := pkg.FullName()
	ctx, ok := r.packageCtxs[pkgName]
	if !ok {
		log.WithField("package", pkgName).Warn("GetGoTestTracer called without active package context")
		return nil
	}

	return NewGoTestTracer(r.tracer, ctx)
}

var _ Reporter = (*OTelReporter)(nil)
var _ TestTracingReporter = (*OTelReporter)(nil)
