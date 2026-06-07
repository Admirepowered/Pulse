package pulse

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	geositeURL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
	geoipURL   = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"
)

type GeodataStatus struct {
	Checking   bool   `json:"checking"`
	Ready      bool   `json:"ready"`
	File       string `json:"file"`
	Message    string `json:"message"`
	Downloaded int64  `json:"downloaded"`
	Total      int64  `json:"total"`
	UpdatedAt  int64  `json:"updatedAt"`
}

type geodataFile struct {
	Name string
	URL  string
}

func (a *App) EnsureGeodata() error {
	a.mu.Lock()
	if a.geodataRunning {
		a.mu.Unlock()
		for {
			time.Sleep(250 * time.Millisecond)
			a.mu.Lock()
			running := a.geodataRunning
			status := a.geodataStatus
			a.mu.Unlock()
			if !running {
				if status.Ready {
					return nil
				}
				if status.Message == "" {
					return errors.New("geodata download failed")
				}
				return errors.New(status.Message)
			}
		}
	}
	if a.geodataStatus.Ready {
		a.mu.Unlock()
		return nil
	}
	a.geodataRunning = true
	a.geodataStatus = GeodataStatus{Checking: true, Message: "checking geodata", UpdatedAt: time.Now().Unix()}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.geodataRunning = false
		a.mu.Unlock()
	}()

	files := []geodataFile{
		{Name: "GeoSite.dat", URL: geositeURL},
		{Name: "geoip.metadb", URL: geoipURL},
	}
	for _, file := range files {
		target := filepath.Join(a.dataDir, file.Name)
		if ok, err := existingNonEmptyFile(target); err == nil && ok {
			continue
		}
		if err := a.copyBundledGeodataFile(file, target); err == nil {
			continue
		} else {
			a.appendLog("warn", "bundled geodata unavailable: "+file.Name+" "+err.Error())
		}
		if err := a.downloadGeodataFile(file, target); err != nil {
			a.appendLog("warn", "github geodata download failed, let mihomo fallback handle it: "+err.Error())
			continue
		}
	}
	a.setGeodataStatus(GeodataStatus{
		Checking:  false,
		Ready:     true,
		Message:   "geodata ready",
		UpdatedAt: time.Now().Unix(),
	})
	return nil
}

func existingNonEmptyFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return !info.IsDir() && info.Size() > 0, nil
}

func (a *App) copyBundledGeodataFile(file geodataFile, target string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	candidates := []string{
		filepath.Join(filepath.Dir(executable), file.Name),
		filepath.Join(filepath.Dir(executable), strings.ToLower(file.Name)),
		filepath.Join(".", file.Name),
		filepath.Join(".", strings.ToLower(file.Name)),
	}
	for _, candidate := range candidates {
		if ok, err := existingNonEmptyFile(candidate); err == nil && ok {
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			input, err := os.Open(candidate)
			if err != nil {
				return err
			}
			defer input.Close()
			tempPath := target + ".part"
			output, err := os.Create(tempPath)
			if err != nil {
				return err
			}
			if _, err := io.Copy(output, input); err != nil {
				_ = output.Close()
				_ = os.Remove(tempPath)
				return err
			}
			if err := output.Close(); err != nil {
				_ = os.Remove(tempPath)
				return err
			}
			if err := os.Rename(tempPath, target); err != nil {
				_ = os.Remove(tempPath)
				return err
			}
			a.appendLog("info", "geodata copied from application directory: "+candidate)
			return nil
		}
	}
	return os.ErrNotExist
}

func (a *App) downloadGeodataFile(file geodataFile, target string) error {
	a.setGeodataStatus(GeodataStatus{
		Checking:  true,
		File:      file.Name,
		Message:   "downloading " + file.Name,
		UpdatedAt: time.Now().Unix(),
	})
	resp, err := a.githubRequest(http.MethodGet, file.URL, nil, map[string]string{"Accept": "application/octet-stream,*/*"})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("download %s returned HTTP %d", file.Name, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tempPath := target + ".part"
	out, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	defer out.Close()
	progress := &progressWriter{
		total: resp.ContentLength,
		onProgress: func(downloaded, total int64) {
			a.setGeodataStatus(GeodataStatus{
				Checking:   true,
				File:       file.Name,
				Message:    "downloading " + file.Name,
				Downloaded: downloaded,
				Total:      total,
				UpdatedAt:  time.Now().Unix(),
			})
		},
	}
	if _, err := io.Copy(out, io.TeeReader(resp.Body, progress)); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if err := os.Rename(tempPath, target); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}

func (a *App) setGeodataStatus(status GeodataStatus) {
	a.mu.Lock()
	a.geodataStatus = status
	a.mu.Unlock()
}

type progressWriter struct {
	downloaded int64
	total      int64
	lastUpdate time.Time
	onProgress func(downloaded, total int64)
}

func (w *progressWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.downloaded += int64(n)
	if time.Since(w.lastUpdate) > 250*time.Millisecond || (w.total > 0 && w.downloaded >= w.total) {
		w.lastUpdate = time.Now()
		w.onProgress(w.downloaded, w.total)
	}
	return n, nil
}
