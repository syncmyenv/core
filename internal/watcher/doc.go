// Package watcher detects changes to protected files.
//
// Editors save atomically (write temp file + rename), which drops watches
// on the file itself, so we watch parent directories, filter by name and
// debounce (~500ms) before hashing and creating a revision.
package watcher
