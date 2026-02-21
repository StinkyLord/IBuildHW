package strategies

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/StinkyLord/cpp-sbom-builder/internal/fingerprints"
	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
)

// MesonStrategy parses meson.build files to detect dependencies declared via
// dependency() calls and wrap files.
type MesonStrategy struct{}

func (s *MesonStrategy) Name() string { return "meson" }

// reMesonDependency matches dependency('foo', ...) calls
var reMesonDependency = regexp.MustCompile(`(?i)dependency\s*\(\s*['"]([A-Za-z0-9_\-\.]+)['"]`)

// reMesonVersion matches version: '>=1.2.3' or version: '1.2.3' in dependency calls
var reMesonVersion = regexp.MustCompile(`version\s*:\s*['"][>=<]*\s*([\d][^\s'"]+)['"]`)

// reMesonSubproject matches subproject('foo') calls
var reMesonSubproject = regexp.MustCompile(`(?i)subproject\s*\(\s*['"]([A-Za-z0-9_\-\.]+)['"]`)

// reMesonWrapVersion matches version = x.y.z in .wrap files
var reMesonWrapVersion = regexp.MustCompile(`(?i)^version\s*=\s*(.+)$`)

// reMesonWrapSource matches source_url or url in .wrap files
var reMesonWrapSource = regexp.MustCompile(`(?i)^(?:source_url|url)\s*=\s*(.+)$`)

func (s *MesonStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	seen := map[string]*model.Component{}

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
		switch {
		case lname == "meson.build":
			if verbose {
				fmt.Printf("  [meson] Parsing meson.build: %s\n", path)
			}
			parseMesonBuild(path, seen)

		case strings.HasSuffix(lname, ".wrap"):
			// Meson wrap files in subprojects/
			if verbose {
				fmt.Printf("  [meson] Parsing wrap file: %s\n", path)
			}
			parseMesonWrap(path, seen)
		}
		return nil
	})

	result := make([]*model.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result, nil
}

func parseMesonBuild(path string, seen map[string]*model.Component) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// Find all dependency() calls
	depMatches := reMesonDependency.FindAllStringSubmatchIndex(content, -1)
	for _, loc := range depMatches {
		depName := content[loc[2]:loc[3]]

		// Skip meson built-in pseudo-dependencies
		if isMesonBuiltin(depName) {
			continue
		}

		fp := fingerprints.MatchLibrary(depName)
		if fp == nil {
			fp = &fingerprints.LibraryFingerprint{
				Name:        strings.ToLower(depName),
				PURL:        "pkg:generic/" + strings.ToLower(depName),
				Description: "Detected via meson dependency()",
			}
		}

		c, ok := seen[fp.Name]
		if !ok {
			c = &model.Component{
				Name:            fp.Name,
				Version:         "unknown",
				PURL:            fp.PURL,
				DetectionSource: "meson",
				Description:     fp.Description,
			}
			seen[fp.Name] = c
		}

		// Look for version constraint in the next 200 chars after the match
		end := loc[1] + 200
		if end > len(content) {
			end = len(content)
		}
		block := content[loc[1]:end]
		if vm := reMesonVersion.FindStringSubmatch(block); vm != nil {
			ver := strings.TrimSpace(vm[1])
			if ver != "" && c.Version == "unknown" {
				c.Version = ver
				c.PURL = fp.PURL + "@" + ver
			}
		}
	}

	// Also detect subproject() calls
	for _, m := range reMesonSubproject.FindAllStringSubmatch(content, -1) {
		subName := m[1]
		if isMesonBuiltin(subName) {
			continue
		}
		fp := fingerprints.MatchLibrary(subName)
		if fp == nil {
			fp = &fingerprints.LibraryFingerprint{
				Name:        strings.ToLower(subName),
				PURL:        "pkg:generic/" + strings.ToLower(subName),
				Description: "Detected via meson subproject()",
			}
		}
		if _, ok := seen[fp.Name]; !ok {
			seen[fp.Name] = &model.Component{
				Name:            fp.Name,
				Version:         "unknown",
				PURL:            fp.PURL,
				DetectionSource: "meson",
				Description:     fp.Description,
			}
		}
	}
}

func parseMesonWrap(path string, seen map[string]*model.Component) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// The wrap file name is the package name
	wrapName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	wrapName = strings.ToLower(wrapName)

	var version string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if m := reMesonWrapVersion.FindStringSubmatch(line); m != nil {
			version = strings.TrimSpace(m[1])
		}
	}

	fp := fingerprints.MatchLibrary(wrapName)
	if fp == nil {
		fp = &fingerprints.LibraryFingerprint{
			Name:        wrapName,
			PURL:        "pkg:generic/" + wrapName,
			Description: "Detected via meson wrap file",
		}
	}

	c, ok := seen[fp.Name]
	if !ok {
		c = &model.Component{
			Name:            fp.Name,
			Version:         "unknown",
			PURL:            fp.PURL,
			DetectionSource: "meson",
			Description:     fp.Description,
		}
		seen[fp.Name] = c
	}
	if version != "" && c.Version == "unknown" {
		c.Version = version
		c.PURL = fp.PURL + "@" + version
	}
}

var mesonBuiltins = map[string]bool{
	"threads": true, "dl": true, "m": true, "rt": true,
	"openmp": true, "mpi": true, "cuda": true,
}

func isMesonBuiltin(name string) bool {
	return mesonBuiltins[strings.ToLower(name)]
}
