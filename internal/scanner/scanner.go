// Package scanner discovers environment files under user-chosen roots.
//
// It never walks the whole filesystem: callers pass explicit roots, and
// well-known dependency/cache directories are pruned.
package scanner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultExcludes are directory names that are never descended into.
var DefaultExcludes = []string{
	".git", "node_modules", "vendor", ".cache", "Library",
	"dist", "build", ".next", ".nuxt", ".turbo", ".venv", "venv",
	"__pycache__", ".terraform", ".gradle", "target", ".idea", ".vscode",
}

// templateSuffixes mark example files that normally contain no secrets.
var templateSuffixes = []string{".example", ".sample", ".template", ".dist", ".defaults"}

// Options configures a scan.
type Options struct {
	Excludes        []string // directory names to prune; nil means DefaultExcludes
	IncludeTemplate bool     // include .env.example & friends
	MaxFileSize     int64    // skip larger files; 0 means 1 MiB
}

// Result is a discovered environment file.
type Result struct {
	Path        string `json:"path"`         // absolute path
	Root        string `json:"root"`         // scan root it was found under
	RelPath     string `json:"rel_path"`     // path relative to Root
	ProjectDir  string `json:"project_dir"`  // git root, else containing dir
	ProjectName string `json:"project_name"` // base name of ProjectDir
	InGitRepo   bool   `json:"in_git_repo"`
	IsTemplate  bool   `json:"is_template"`
	Size        int64  `json:"size"`
}

// IsEnvFile reports whether a file name looks like an environment file:
// .env, .env.<anything>, env, env.<anything>.
func IsEnvFile(name string) bool {
	for _, base := range []string{".env", "env"} {
		if name == base || strings.HasPrefix(name, base+".") && len(name) > len(base)+1 {
			return true
		}
	}
	return false
}

// IsTemplate reports whether the env file is an example/template file.
func IsTemplate(name string) bool {
	for _, s := range templateSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// Scan walks each root and returns env files sorted by path.
func Scan(roots []string, opt Options) ([]Result, error) {
	excludes := opt.Excludes
	if excludes == nil {
		excludes = DefaultExcludes
	}
	skip := make(map[string]bool, len(excludes))
	for _, e := range excludes {
		skip[e] = true
	}
	maxSize := opt.MaxFileSize
	if maxSize == 0 {
		maxSize = 1 << 20
	}

	seen := map[string]bool{}
	gitCache := map[string]string{}
	var out []Result

	for _, root := range roots {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(absRoot)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, errors.New(absRoot + " is not a directory")
		}

		err = filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrPermission) {
					if d != nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if p != absRoot && skip[name] {
					return fs.SkipDir
				}
				return nil
			}
			// Regular files only: symlinks could point anywhere.
			if !d.Type().IsRegular() || !IsEnvFile(name) || seen[p] {
				return nil
			}
			tmpl := IsTemplate(name)
			if tmpl && !opt.IncludeTemplate {
				return nil
			}
			fi, err := d.Info()
			if err != nil || fi.Size() > maxSize {
				return nil
			}
			seen[p] = true
			rel, _ := filepath.Rel(absRoot, p)
			proj, inGit := projectDir(filepath.Dir(p), absRoot, gitCache)
			out = append(out, Result{
				Path: p, Root: absRoot, RelPath: rel,
				ProjectDir: proj, ProjectName: filepath.Base(proj),
				InGitRepo: inGit, IsTemplate: tmpl, Size: fi.Size(),
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// projectDir finds the nearest git root at or above dir (not above root).
// Without one, the file's own directory is the project.
func projectDir(dir, root string, cache map[string]string) (string, bool) {
	if v, ok := cache[dir]; ok {
		return v, v != ""
	}
	for cur := dir; ; cur = filepath.Dir(cur) {
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			cache[dir] = cur
			return cur, true
		}
		if cur == root || cur == filepath.Dir(cur) {
			break
		}
	}
	cache[dir] = ""
	return dir, false
}

// ProjectOf names the project a file belongs to: the nearest git root above
// it (up to the home directory), else its parent directory.
func ProjectOf(path string) string {
	dir := filepath.Dir(path)
	home, _ := os.UserHomeDir()
	for cur := dir; ; cur = filepath.Dir(cur) {
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			return filepath.Base(cur)
		}
		if cur == home || cur == filepath.Dir(cur) {
			break
		}
	}
	return filepath.Base(dir)
}
