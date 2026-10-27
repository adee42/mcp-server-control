package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/adee42/mcp-server-control/internal/api"
)

const maxDirEntries = 5000

func (s *Server) handleFileRead(r *http.Request, k *Key) (any, error) {
	p := r.URL.Query().Get("path")
	note(r, slog.String("file", p))
	resolved, err := k.checkPath(p, false)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return nil, fsError(err)
	}
	if fi.IsDir() {
		return nil, errStatus(http.StatusBadRequest, p+" is a directory; list it instead")
	}
	if max := int64(s.config().Limits.MaxFile); fi.Size() > max {
		return nil, errStatus(http.StatusRequestEntityTooLarge, fmt.Sprintf("file is %d bytes, limit is %d", fi.Size(), max))
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fsError(err)
	}
	note(r, slog.String("resolved", resolved), slog.Int("bytes", len(data)))
	return api.FileContent{
		Path:       resolved,
		Size:       int64(len(data)),
		Mode:       fmt.Sprintf("%04o", fi.Mode().Perm()),
		ModTime:    fi.ModTime(),
		ContentB64: base64.StdEncoding.EncodeToString(data),
	}, nil
}

func (s *Server) handleFileWrite(r *http.Request, k *Key) (any, error) {
	p := r.URL.Query().Get("path")
	note(r, slog.String("file", p))
	maxFile := int64(s.config().Limits.MaxFile)
	var req api.FileWrite
	if err := decodeBody(r, smallBody+int64(base64.StdEncoding.EncodedLen(int(maxFile))), &req); err != nil {
		return nil, err
	}
	resolved, err := k.checkPath(p, true)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(req.ContentB64)
	if err != nil {
		return nil, errStatus(http.StatusBadRequest, "content_b64 is not valid base64")
	}
	if int64(len(data)) > maxFile {
		return nil, errStatus(http.StatusRequestEntityTooLarge, fmt.Sprintf("content is %d bytes, limit is %d", len(data), maxFile))
	}

	mode := os.FileMode(0o644)
	existing, err := os.Stat(resolved)
	switch {
	case err == nil && existing.IsDir():
		return nil, errStatus(http.StatusBadRequest, p+" is a directory")
	case err == nil:
		mode = existing.Mode().Perm()
	case errors.Is(err, fs.ErrNotExist):
		existing = nil
	default:
		return nil, fsError(err)
	}
	if req.Mode != "" {
		m, err := strconv.ParseUint(req.Mode, 8, 32)
		if err != nil || m > 0o7777 {
			return nil, errStatus(http.StatusBadRequest, "mode must be an octal string such as 0644")
		}
		mode = os.FileMode(m)
	}

	dir := filepath.Dir(resolved)
	if req.MkdirAll {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fsError(err)
		}
	} else if _, err := os.Stat(dir); err != nil {
		return nil, errStatus(http.StatusNotFound, "parent directory does not exist (set mkdir_all to create it)")
	}
	if err := writeFileAtomic(resolved, data, mode, existing); err != nil {
		return nil, fsError(err)
	}
	note(r, slog.String("resolved", resolved), slog.Int("bytes", len(data)), slog.String("mode", fmt.Sprintf("%04o", mode)), slog.Bool("created", existing == nil))
	return api.FileWriteResult{Path: resolved, Size: int64(len(data))}, nil
}

func (s *Server) handleFileList(r *http.Request, k *Key) (any, error) {
	p := r.URL.Query().Get("path")
	note(r, slog.String("file", p))
	resolved, err := k.checkPath(p, false)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return nil, fsError(err)
	}
	out := api.DirListing{Path: resolved, Entries: []api.DirEntry{}}
	for i, e := range entries {
		if i == maxDirEntries {
			break
		}
		de := api.DirEntry{Name: e.Name(), IsDir: e.IsDir()}
		if fi, err := e.Info(); err == nil {
			de.Size = fi.Size()
			de.Mode = fi.Mode().String()
			de.ModTime = fi.ModTime()
		}
		out.Entries = append(out.Entries, de)
	}
	return out, nil
}

func fsError(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return errStatus(http.StatusNotFound, err.Error())
	case errors.Is(err, fs.ErrPermission):
		return errStatus(http.StatusForbidden, err.Error())
	}
	return err
}

// writeFileAtomic writes data to a temp file next to path and renames it into place.
// When existing is set, the new file keeps that file's owner.
func writeFileAtomic(path string, data []byte, mode os.FileMode, existing os.FileInfo) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if existing != nil {
		copyOwner(f, existing)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
