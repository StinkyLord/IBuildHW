package strategies

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/StinkyLord/cpp-sbom-builder/internal/fingerprints"
	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
)

// HeadersStrategy scans C/C++ source and header files for #include directives.
// It is used as a FALLBACK when no compiler artifacts are available.
// It filters out:
//  1. Standard library headers (via the stdlib allowlist in fingerprints)
//  2. Project-internal headers (quoted includes that resolve inside the project)
//  3. Relative includes ("../foo.h")
//
// Only angle-bracket includes that match a known library fingerprint are reported.
type HeadersStrategy struct{}

func (s *HeadersStrategy) Name() string { return "header-scan" }

// reIncludeDirective matches #include <foo/bar.h> and #include "foo/bar.h"
var reIncludeDirective = regexp.MustCompile(`^\s*#\s*include\s*([<"])([^>"]+)[>"]`)

// reVersionDefine matches version macros in header files:
// #define FOO_VERSION_MAJOR 1
// #define FOO_VERSION "1.2.3"
var reVersionDefine = regexp.MustCompile(`(?i)#\s*define\s+[A-Z_]*VERSION[A-Z_]*\s+"?([\d][.\d]+)"?`)

// cppSourceExts is the set of file extensions to scan for includes.
var cppSourceExts = map[string]bool{
	".cpp": true, ".cc": true, ".cxx": true, ".c++": true,
	".c": true,
	".h": true, ".hpp": true, ".hxx": true, ".h++": true, ".hh": true,
	".inl": true, ".ipp": true, ".tpp": true,
}

func (s *HeadersStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	seen := map[string]*model.Component{}
	fileCount := 0

	_ = filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			// Skip hidden dirs, build output dirs, and vendor dirs
			if strings.HasPrefix(name, ".") ||
				name == "node_modules" ||
				name == "CMakeFiles" ||
				name == "build" ||
				name == "out" ||
				name == "_build" ||
				name == ".build" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !cppSourceExts[ext] {
			return nil
		}

		fileCount++
		scanSourceFile(path, projectRoot, seen, verbose)
		return nil
	})

	if verbose {
		fmt.Printf("  [header-scan] Scanned %d source/header files\n", fileCount)
	}

	result := make([]*model.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result, nil
}

func scanSourceFile(path, projectRoot string, seen map[string]*model.Component, verbose bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := reIncludeDirective.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		bracket := m[1] // '<' or '"'
		include := m[2]

		// Skip quoted includes — these are almost always project-internal
		if bracket == `"` {
			// Unless the path is clearly external (absolute path in a quoted include)
			if !filepath.IsAbs(include) {
				continue
			}
		}

		// Skip standard library headers
		if fingerprints.IsStdlibHeader(include) {
			continue
		}

		// Skip if the include resolves to a file inside the project
		if resolvedInsideProject(include, path, projectRoot) {
			continue
		}

		// Try to match against known library fingerprints
		fp := fingerprints.MatchLibrary(include)
		if fp == nil {
			continue
		}

		c, ok := seen[fp.Name]
		if !ok {
			c = &model.Component{
				Name:            fp.Name,
				Version:         "unknown",
				PURL:            fp.PURL,
				DetectionSource: "header-scan",
				Description:     fp.Description,
			}
			seen[fp.Name] = c
		}
		c.IncludePaths = appendUnique(c.IncludePaths, include)
	}
}

// resolvedInsideProject checks whether an include path resolves to a file
// that exists inside the project root (i.e., it's an internal header).
func resolvedInsideProject(include, sourceFile, projectRoot string) bool {
	// Check relative to the source file's directory
	sourceDir := filepath.Dir(sourceFile)
	candidate := filepath.Join(sourceDir, include)
	if _, err := os.Stat(candidate); err == nil {
		// File exists relative to source — internal
		abs, _ := filepath.Abs(candidate)
		absRoot, _ := filepath.Abs(projectRoot)
		if strings.HasPrefix(
			filepath.ToSlash(strings.ToLower(abs)),
			filepath.ToSlash(strings.ToLower(absRoot)),
		) {
			return true
		}
	}

	// Check relative to project root
	candidate = filepath.Join(projectRoot, include)
	if _, err := os.Stat(candidate); err == nil {
		return true
	}

	// Check common internal include dirs
	for _, dir := range []string{"include", "src", "lib", "third_party", "external"} {
		candidate = filepath.Join(projectRoot, dir, include)
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
	}

	return false
}

// ScanVersionHints scans header files in known external include paths for
// version-defining macros. This is called by the scanner after all strategies
// have run to attempt to fill in "unknown" versions.
func ScanVersionHints(components []*model.Component, projectRoot string) {
	for _, c := range components {
		if c.Version != "unknown" {
			continue
		}
		for _, incPath := range c.IncludePaths {
			// incPath might be a directory like /usr/include/boost
			// or a header file like boost/version.hpp
			v := scanDirForVersion(incPath)
			if v != "" {
				c.Version = v
				// Update PURL
				if strings.Contains(c.PURL, "@") {
					parts := strings.SplitN(c.PURL, "@", 2)
					c.PURL = parts[0] + "@" + v
				} else {
					c.PURL = c.PURL + "@" + v
				}
				break
			}
		}
	}
}

// scanDirForVersion looks for version-defining macros in header files
// within the given directory or file path.
func scanDirForVersion(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}

	if !info.IsDir() {
		return scanFileForVersion(path)
	}

	// Look for version.h, *_version.h, *_config.h, version.hpp
	versionFiles := []string{
		"version.h", "version.hpp", "Version.h",
		"config.h", "config.hpp",
	}

	// Also walk the directory for files matching *version* or *config*
	var candidates []string
	for _, vf := range versionFiles {
		candidates = append(candidates, filepath.Join(path, vf))
	}

	_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		lname := strings.ToLower(d.Name())
		if strings.Contains(lname, "version") || strings.Contains(lname, "config") {
			candidates = append(candidates, p)
		}
		return nil
	})

	for _, cf := range candidates {
		if v := scanFileForVersion(cf); v != "" {
			return v
		}
	}
	return ""
}

func scanFileForVersion(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := reVersionDefine.FindStringSubmatch(line); m != nil {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}
