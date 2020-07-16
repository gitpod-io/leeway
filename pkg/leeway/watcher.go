package leeway

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"github.com/typefox/leeway/pkg/doublestar"
)

// WatchSources watches the source files of the packages until the context is done
func WatchSources(ctx context.Context, pkgs []*Package) (changed <-chan string, errs <-chan error) {
	var (
		chng    = make(chan string)
		errchan = make(chan error, 1)
	)
	changed = chng
	errs = errchan

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		errchan <- err
		return
	}

	var (
		matcher []*pathMatcher
		folders = make(map[string]*Package)
	)
	for _, pkg := range pkgs {
		for _, src := range pkg.Sources {
			folders[filepath.Dir(src)] = pkg
		}
	}
	for f, pkg := range folders {
		log.WithField("path", f).Debug("adding watcher")
		watcher.Add(f)

		matcher = append(matcher, &pathMatcher{
			Base:     f,
			Patterns: pkg.originalSources,
		})
	}

	go func() {
		defer watcher.Close()
		for {
			select {
			case evt := <-watcher.Events:
				var (
					patterns []string
					matches  bool
				)
				for _, m := range matcher {
					if m.Matches(evt.Name) {
						matches = true
						patterns = m.Patterns
						break
					}
				}
				if !matches {
					log.WithField("path", evt.Name).Debug("dismissed file event that did not match source globs")
					return
				}

				dfn := filepath.Dir(evt.Name)
				if _, ok := folders[dfn]; !ok {
					matcher = append(matcher, &pathMatcher{
						Base:     dfn,
						Patterns: patterns,
					})
					watcher.Add(dfn)
					log.WithField("path", dfn).Debug("added new source folder")
				}

				log.WithField("path", evt.Name).Debug("source file changed")
				chng <- evt.Name
			case err := <-watcher.Errors:
				errchan <- err
			case <-ctx.Done():
				return
			}
		}
	}()

	return
}

type pathMatcher struct {
	Base     string
	Patterns []string
}

func (pm *pathMatcher) Matches(path string) bool {
	if strings.HasPrefix(path, pm.Base) {
		return false
	}
	for _, p := range pm.Patterns {
		matches, _ := doublestar.Match(p, strings.TrimPrefix(strings.TrimPrefix(path, pm.Base), "/"))
		if matches {
			return true
		}
	}
	return false
}
