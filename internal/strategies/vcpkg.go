package strategies

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/StinkyLord/cpp-sbom-builder/internal/fingerprints"
	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
)

// VcpkgStrategy parses vcpkg package manager files:
//   - vcpkg.json          (manifest mode)
//   - vcpkg-lock.json     (lock file)
//   - installed/vcpkg/status (classic mode installed packages)
type VcpkgStrategy struct{}

func (s *VcpkgStrategy) Name() string { return "vcpkg" }

// vcpkgManifest represents vcpkg.json
type vcpkgManifest struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies []vcpkgDependency `json:"dependencies"`
}

type vcpkgDependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Dependencies can also be plain strings
}

// vcpkgLock represents vcpkg-lock.json (simplified)
type vcpkgLock struct {
	Packages map[string]vcpkgLockPackage `json:"packages"`
}

type vcpkgLockPackage struct {
	Version string `json:"version"`
}

func (s *VcpkgStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	var components []*model.Component

	_ = filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".git") {
				return filepath.SkipDir
			}
			return nil
		}

		lname := strings.ToLower(d.Name())
		switch lname {
		case "vcpkg.json":
			if verbose {
				fmt.Printf("  [vcpkg] Parsing vcpkg.json: %s\n", path)
			}
			comps := parseVcpkgManifest(path)
			components = append(components, comps...)

		case "vcpkg-lock.json":
			if verbose {
				fmt.Printf("  [vcpkg] Parsing vcpkg-lock.json: %s\n", path)
			}
			comps := parseVcpkgLock(path)
			components = append(components, comps...)

		case "status":
			// vcpkg classic mode: installed/vcpkg/status
			if strings.Contains(filepath.ToSlash(path), "vcpkg/status") ||
				strings.Contains(filepath.ToSlash(path), "installed/vcpkg") {
				if verbose {
					fmt.Printf("  [vcpkg] Parsing vcpkg status: %s\n", path)
				}
				comps := parseVcpkgStatus(path)
				components = append(components, comps...)
			}
		}
		return nil
	})

	return components, nil
}

func parseVcpkgManifest(path string) []*model.Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// vcpkg.json dependencies can be strings or objects
	var raw struct {
		Dependencies []json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var components []*model.Component
	for _, dep := range raw.Dependencies {
		// Try as string first
		var name string
		if err := json.Unmarshal(dep, &name); err == nil {
			c := makeVcpkgComponent(name, "unknown")
			components = append(components, c)
			continue
		}
		// Try as object
		var obj vcpkgDependency
		if err := json.Unmarshal(dep, &obj); err == nil && obj.Name != "" {
			c := makeVcpkgComponent(obj.Name, obj.Version)
			components = append(components, c)
		}
	}
	return components
}

func parseVcpkgLock(path string) []*model.Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// vcpkg-lock.json has various formats across versions.
	// Try the packages map format.
	var lock vcpkgLock
	if err := json.Unmarshal(data, &lock); err == nil && len(lock.Packages) > 0 {
		var components []*model.Component
		for name, pkg := range lock.Packages {
			// Strip triplet suffix: "boost:x64-windows" -> "boost"
			name = strings.SplitN(name, ":", 2)[0]
			c := makeVcpkgComponent(name, pkg.Version)
			components = append(components, c)
		}
		return components
	}

	// Try flat array format used in newer vcpkg
	var arr []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &arr); err == nil {
		var components []*model.Component
		for _, item := range arr {
			if item.Name != "" {
				c := makeVcpkgComponent(item.Name, item.Version)
				components = append(components, c)
			}
		}
		return components
	}

	return nil
}

// parseVcpkgStatus parses the dpkg-style status file used by vcpkg classic mode.
// Format:
//
//	Package: boost-system
//	Version: 1.82.0
//	Status: install ok installed
func parseVcpkgStatus(path string) []*model.Component {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var components []*model.Component
	var curName, curVersion string
	installed := false

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			// End of a stanza
			if installed && curName != "" {
				c := makeVcpkgComponent(curName, curVersion)
				components = append(components, c)
			}
			curName = ""
			curVersion = ""
			installed = false
			continue
		}
		if strings.HasPrefix(line, "Package:") {
			curName = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
			// Strip triplet: boost-system:x64-windows -> boost-system
			curName = strings.SplitN(curName, ":", 2)[0]
		} else if strings.HasPrefix(line, "Version:") {
			curVersion = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		} else if strings.HasPrefix(line, "Status:") && strings.Contains(line, "installed") {
			installed = true
		}
	}
	// Handle last stanza
	if installed && curName != "" {
		c := makeVcpkgComponent(curName, curVersion)
		components = append(components, c)
	}

	return components
}

func makeVcpkgComponent(name, version string) *model.Component {
	if version == "" {
		version = "unknown"
	}
	fp := fingerprints.MatchLibrary(name)
	purl := "pkg:generic/" + name
	if version != "unknown" {
		purl += "@" + version
	}
	desc := ""
	if fp != nil {
		purl = fp.PURL
		if version != "unknown" {
			purl += "@" + version
		}
		desc = fp.Description
	}
	return &model.Component{
		Name:            name,
		Version:         version,
		PURL:            purl,
		DetectionSource: "vcpkg",
		Description:     desc,
	}
}
