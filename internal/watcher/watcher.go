// Package watcher turns filesystem events on protected files into sealed
// revisions, automatically.
//
// Editors save atomically (write a temp file, rename it over the original),
// which drops a watch on the file itself. So we watch each protected file's
// *parent directory*, filter events by name, and debounce bursts of events
// before snapshotting. A periodic reconcile catches anything missed (e.g.
// events dropped while the machine slept) and picks up newly protected files.
package watcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/syncmyenv/core/internal/vault"
)

// Options tune the watcher. Zero values get sensible defaults.
type Options struct {
	Debounce  time.Duration // quiet period after the last event (default 500ms)
	Reload    time.Duration // how often to re-read the protected file list (default 10s)
	Reconcile time.Duration // full snapshot of everything (default 5m)

	// OnSnapshot is called for each file that got a new revision or problem.
	OnSnapshot func(vault.SnapshotResult)
	// OnError reports non-fatal errors (a directory that can't be watched…).
	OnError func(error)
}

func (o *Options) defaults() {
	if o.Debounce == 0 {
		o.Debounce = 500 * time.Millisecond
	}
	if o.Reload == 0 {
		o.Reload = 10 * time.Second
	}
	if o.Reconcile == 0 {
		o.Reconcile = 5 * time.Minute
	}
	if o.OnSnapshot == nil {
		o.OnSnapshot = func(vault.SnapshotResult) {}
	}
	if o.OnError == nil {
		o.OnError = func(error) {}
	}
}

// Watcher watches protected files and snapshots them on change.
type Watcher struct {
	v    *vault.Vault
	opts Options
	fsw  *fsnotify.Watcher

	mu      sync.Mutex
	files   map[string]bool // protected paths
	dirs    map[string]bool // watched parent dirs
	pending map[string]bool // changed, waiting for debounce
}

// New creates a watcher for v. Call Run to start it.
func New(v *vault.Vault, opts Options) (*Watcher, error) {
	opts.defaults()
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Watcher{v: v, opts: opts, fsw: fsw, files: map[string]bool{}, dirs: map[string]bool{}, pending: map[string]bool{}}, nil
}

// Watching returns the currently watched files (sorted), for status output.
func (w *Watcher) Watching() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.files))
	for p := range w.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Run blocks until ctx is cancelled. It first snapshots everything, to catch
// changes made while the daemon wasn't running.
func (w *Watcher) Run(ctx context.Context) error {
	defer w.fsw.Close()
	if err := w.reload(ctx); err != nil {
		return err
	}
	w.snapshot(ctx, nil)

	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	reload := time.NewTicker(w.opts.Reload)
	defer reload.Stop()
	reconcile := time.NewTicker(w.opts.Reconcile)
	defer reconcile.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-w.fsw.Events:
			if !ok {
				return errors.New("watcher: event channel closed")
			}
			if w.isProtected(ev.Name) {
				w.mu.Lock()
				w.pending[filepath.Clean(ev.Name)] = true
				w.mu.Unlock()
				debounce.Reset(w.opts.Debounce)
			}

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return errors.New("watcher: error channel closed")
			}
			// Overflow means we may have missed events: reconcile everything.
			w.opts.OnError(err)
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				w.snapshot(ctx, nil)
			}

		case <-debounce.C:
			w.mu.Lock()
			paths := make([]string, 0, len(w.pending))
			for p := range w.pending {
				paths = append(paths, p)
			}
			w.pending = map[string]bool{}
			w.mu.Unlock()
			w.snapshot(ctx, paths)

		case <-reload.C:
			if err := w.reload(ctx); err != nil {
				w.opts.OnError(err)
			}

		case <-reconcile.C:
			w.snapshot(ctx, nil)
		}
	}
}

func (w *Watcher) isProtected(p string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.files[filepath.Clean(p)]
}

func (w *Watcher) snapshot(ctx context.Context, paths []string) {
	if paths != nil && len(paths) == 0 {
		return
	}
	res, err := w.v.SnapshotPaths(ctx, paths)
	if err != nil {
		w.opts.OnError(err)
		return
	}
	for _, r := range res {
		if r.Seq > 0 || r.Error != "" {
			w.opts.OnSnapshot(r)
		}
	}
}

// reload syncs watches with the vault's protected files: new protects start
// being watched, unprotected files stop, and parent dirs that appeared
// (e.g. a re-cloned project) get picked up.
func (w *Watcher) reload(ctx context.Context) error {
	list, err := w.v.List(ctx)
	if err != nil {
		return err
	}
	files := make(map[string]bool, len(list))
	wantDirs := map[string]bool{}
	for _, f := range list {
		files[f.Path] = true
		wantDirs[filepath.Dir(f.Path)] = true
	}

	w.mu.Lock()
	added := []string{}
	for p := range files {
		if !w.files[p] {
			added = append(added, p)
		}
	}
	w.files = files
	w.mu.Unlock()

	for d := range wantDirs {
		if w.dirs[d] {
			continue
		}
		if _, err := os.Stat(d); err != nil {
			continue // dir gone for now; retry next reload
		}
		if err := w.fsw.Add(d); err != nil {
			w.opts.OnError(err)
			continue
		}
		w.dirs[d] = true
	}
	for d := range w.dirs {
		if !wantDirs[d] {
			_ = w.fsw.Remove(d)
			delete(w.dirs, d)
		} else if _, err := os.Stat(d); err != nil {
			delete(w.dirs, d) // removed dir: fsnotify dropped it; re-add when it returns
		}
	}
	// Newly protected files: capture any edits made between protect and now.
	if len(added) > 0 && len(added) != len(files) {
		w.snapshot(ctx, added)
	}
	return nil
}
