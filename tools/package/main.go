// Command package builds unsigned evaluation archives from the repository root.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	mipam "mipam/internal/version"
)

const version = mipam.Version

type entry struct {
	name, source string
	mode         int64
}

func main() {
	if err := build(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build() error {
	if _, err := os.Stat("go.mod"); err != nil {
		return fmt.Errorf("run from the repository root: %w", err)
	}
	out := filepath.Join("dist", "release")
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp("", "mipam-package-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	var sums []string
	for _, target := range []struct{ os, arch string }{{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}} {
		name := "mipam-" + version + "-" + target.os + "-" + target.arch
		dir := filepath.Join(stage, name)
		if err := os.Mkdir(dir, 0755); err != nil {
			return err
		}
		files := []entry{{"README.md", "README.md", 0644}, {"CHANGELOG.md", "CHANGELOG.md", 0644},
			{"ROADMAP.md", "ROADMAP.md", 0644}, {"config.example.json", "config.example.json", 0644},
			{"integrations.example.json", "integrations.example.json", 0644},
			{"subnets.example.csv", "examples/subnets.csv", 0644}}
		commands := []string{"mipam"}
		extension := ""
		if target.os == "windows" {
			extension = ".exe"
			commands = append(commands, "mipam-connector")
			files = append(files, entry{"connector.example.json", "connector.example.json", 0644},
				entry{"Install.ps1", "packaging/windows/Install.ps1", 0644}, entry{"Uninstall.ps1", "packaging/windows/Uninstall.ps1", 0644})
		} else {
			files = append(files, entry{"install.sh", "packaging/linux/install.sh", 0755},
				entry{"uninstall.sh", "packaging/linux/uninstall.sh", 0755}, entry{"mipam.service", "packaging/linux/mipam.service", 0644})
		}
		for _, command := range commands {
			binary := filepath.Join(dir, command+extension)
			cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", binary, "./cmd/"+command)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+target.os, "GOARCH="+target.arch)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			fmt.Printf("Building %s/%s %s\n", target.os, target.arch, command)
			if err := cmd.Run(); err != nil {
				return err
			}
			sbom := binary + ".cdx.json"
			if err := writeSBOM(binary, sbom, command); err != nil {
				return err
			}
			files = append(files, entry{command + extension, binary, 0755}, entry{command + ".cdx.json", sbom, 0644})
		}
		sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
		archive := filepath.Join(out, name+".tar.gz")
		if target.os == "windows" {
			archive = filepath.Join(out, name+".zip")
		}
		if err := writeArchive(archive, name, files, target.os == "windows"); err != nil {
			return err
		}
		f, err := os.Open(archive)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		sums = append(sums, hex.EncodeToString(h.Sum(nil))+"  "+filepath.Base(archive))
	}
	return os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(strings.Join(sums, "\n")+"\n"), 0644)
}

func writeSBOM(binary, destination, name string) error {
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return err
	}
	components := []map[string]any{{"type": "framework", "name": "Go", "version": info.GoVersion}}
	for _, dep := range info.Deps {
		if dep.Replace != nil {
			dep = dep.Replace
		}
		components = append(components, map[string]any{"type": "library", "name": dep.Path, "version": dep.Version,
			"purl": "pkg:golang/" + dep.Path + "@" + dep.Version})
	}
	data, err := json.MarshalIndent(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata":   map[string]any{"component": map[string]any{"type": "application", "name": name, "version": version}},
		"components": components,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(destination, append(data, '\n'), 0644)
}

func writeArchive(path, prefix string, files []entry, windows bool) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if e := f.Close(); err == nil {
			err = e
		}
	}()
	if windows {
		z := zip.NewWriter(f)
		for _, file := range files {
			header := &zip.FileHeader{Name: prefix + "/" + file.name, Method: zip.Deflate}
			header.SetMode(os.FileMode(file.mode))
			header.SetModTime(time.Unix(315532800, 0).UTC())
			w, e := z.CreateHeader(header)
			if e != nil {
				return e
			}
			if e = copyFile(w, file.source); e != nil {
				return e
			}
		}
		return z.Close()
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, file := range files {
		stat, e := os.Stat(file.source)
		if e != nil {
			return e
		}
		if e = tw.WriteHeader(&tar.Header{Name: prefix + "/" + file.name, Mode: file.mode, Size: stat.Size(), ModTime: time.Unix(0, 0)}); e != nil {
			return e
		}
		if e = copyFile(tw, file.source); e != nil {
			return e
		}
	}
	if err = tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func copyFile(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}
