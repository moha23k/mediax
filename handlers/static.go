package handlers

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

func ServeStaticFiles(prefix string, fs fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(fs))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strippedPath := strings.TrimPrefix(r.URL.Path, prefix)

		cleanedPath := path.Clean("/" + strippedPath)
		fsPath := strings.TrimPrefix(cleanedPath, "/")

		if strings.Contains(fsPath, "..") {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		checkPath := fsPath
		if checkPath == "" {
			checkPath = "."
		}

		f, err := fs.Open(checkPath)
		if err == nil {
			defer f.Close()
			stat, err := f.Stat()
			if err == nil && stat.IsDir() {
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
		}

		originalPath := r.URL.Path
		defer func() {
			r.URL.Path = originalPath
		}()
		r.URL.Path = cleanedPath

		fileServer.ServeHTTP(w, r)
	})
}
