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

// LinkerMapStrategy parses linker map files (.map) produced by MSVC (/MAP flag)
// or GCC/Clang (-Map flag). These files list every library and object file that
// was linked, making it trivial to identify external dependencies.
//
// Additionally, GNU linker maps contain a "satisfy reference" section that
// encodes parent→child edges:
//
//	Archive member included to satisfy reference by file (symbol)
//	/usr/lib/libz.so.1    (libssl.so.3(deflate))
//
// This means libssl pulled in libz — a real transitive dependency edge.
type LinkerMapStrategy struct{}

func (s *LinkerMapStrategy) Name() string { return "linker-map" }

// LinkerMapResult holds components and the dependency edges extracted from map files.
type LinkerMapResult struct {
	Components []*model.Component
	// Edges maps package name -> list of child package names (from "satisfy reference")
	Edges map[string][]string
}

// reMapLibEntry matches library paths in MSVC and GNU map files.
// MSVC format: lines containing .lib paths
// GNU format:  LOAD /path/to/libfoo.a  or  /path/to/libfoo.so
var reMapLibEntry = regexp.MustCompile(`(?i)(?:LOAD\s+|^\s*)([A-Za-z]:[\\\/][^\s]+\.(?:lib|a|so(?:\.\d+)*)|\/[^\s]+\.(?:lib|a|so(?:\.\d+)*))`)

// reMSVCLibLine matches lines in MSVC map files that reference .lib files
var reMSVCLibLine = regexp.MustCompile(`(?i)([A-Za-z]:[\\\/][^\s"]+\.lib|[^\s"]+\.lib)`)

// reSatisfyRef matches the GNU linker "satisfy reference" lines:
//
//	/path/to/libchild.so    (/path/to/libparent.so(symbol))
//	/path/to/libchild.a(obj.o)    (libparent.so(symbol))
var reSatisfyRef = regexp.MustCompile(`^\s*([^\s(]+(?:\.(?:so|a|lib)(?:\.\d+)*)?)(?:\([^)]*\))?\s+\(([^\s(]+(?:\.(?:so|a|lib)(?:\.\d+)*)?)`)

func (s *LinkerMapStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	r := s.ScanWithEdges(projectRoot, verbose)
	return r.Components, nil
}

// ScanWithEdges returns both components and the dependency edges.
func (s *LinkerMapStrategy) ScanWithEdges(projectRoot string, verbose bool) *LinkerMapResult {
	result := &LinkerMapResult{
		Edges: map[string][]string{},
	}

	var mapFiles []string
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
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".map" {
			mapFiles = append(mapFiles, path)
		}
		return nil
	})

	if len(mapFiles) == 0 {
		if verbose {
			fmt.Println("  [linker-map] No .map files found")
		}
		return result
	}

	externalLibPaths := map[string]bool{}

	for _, mf := range mapFiles {
		if verbose {
			fmt.Printf("  [linker-map] Parsing %s\n", mf)
		}
		s.parseMapFile(mf, projectRoot, externalLibPaths, result.Edges, verbose)
	}

	if len(externalLibPaths) == 0 {
		return result
	}

	seen := map[string]*model.Component{}
	for libPath := range externalLibPaths {
		fp := fingerprints.MatchLibrary(libPath)
		if fp == nil {
			fp = fingerprints.MatchLibrary(filepath.Base(libPath))
		}
		if fp == nil {
			continue
		}
		c, ok := seen[fp.Name]
		if !ok {
			c = &model.Component{
				Name:            fp.Name,
				Version:         "unknown",
				PURL:            fp.PURL,
				DetectionSource: s.Name(),
				Description:     fp.Description,
			}
			seen[fp.Name] = c
		}
		c.LinkLibraries = appendUnique(c.LinkLibraries, filepath.Base(libPath))
		if v := extractVersionFromPath(libPath); v != "" && c.Version == "unknown" {
			c.Version = v
			c.PURL = fp.PURL + "@" + v
		}
		if v := extractVersionFromLibName(filepath.Base(libPath)); v != "" && c.Version == "unknown" {
			c.Version = v
			c.PURL = fp.PURL + "@" + v
		}
	}

	for _, c := range seen {
		result.Components = append(result.Components, c)
	}
	return result
}

func (s *LinkerMapStrategy) parseMapFile(
	path, projectRoot string,
	externalLibPaths map[string]bool,
	edges map[string][]string,
	verbose bool,
) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	// State machine: track whether we are inside the "satisfy reference" section
	inSatisfySection := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Detect the GNU "Archive member included to satisfy reference" section header
		if strings.Contains(line, "Archive member included") && strings.Contains(line, "satisfy") {
			inSatisfySection = true
			continue
		}
		// The satisfy section ends at the next blank line followed by a non-indented line
		// (heuristic: if we see a line that starts with a non-space and doesn't look like
		// a library path, we've left the section)
		if inSatisfySection {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				// blank line — stay in section, next line will tell us
				continue
			}
			// If the line matches the satisfy reference pattern, parse it
			if m := reSatisfyRef.FindStringSubmatch(line); m != nil {
				childPath := strings.TrimSpace(m[1])
				parentPath := strings.TrimSpace(m[2])

				// Record both as external lib paths
				if isExternalPath(childPath, projectRoot) {
					externalLibPaths[filepath.ToSlash(childPath)] = true
				}
				if isExternalPath(parentPath, projectRoot) {
					externalLibPaths[filepath.ToSlash(parentPath)] = true
				}

				// Map to package names and record the edge
				childPkg := libNameToPackage(filepath.Base(childPath))
				parentPkg := libNameToPackage(filepath.Base(parentPath))
				if childPkg != nil && parentPkg != nil && childPkg.Name != parentPkg.Name {
					if verbose {
						fmt.Printf("  [linker-map] edge: %s → %s (satisfy reference)\n",
							parentPkg.Name, childPkg.Name)
					}
					edges[parentPkg.Name] = appendUnique(edges[parentPkg.Name], childPkg.Name)
				}
				continue
			}
			// If the line doesn't look like a library path, we've left the section
			if !strings.HasPrefix(trimmed, "/") && !strings.Contains(trimmed, ":\\") {
				inSatisfySection = false
			}
		}

		// Always collect library paths regardless of section
		if m := reMapLibEntry.FindStringSubmatch(line); m != nil {
			libPath := m[1]
			if isExternalPath(libPath, projectRoot) {
				externalLibPaths[filepath.ToSlash(libPath)] = true
			}
		}
		for _, m := range reMSVCLibLine.FindAllStringSubmatch(line, -1) {
			libPath := m[1]
			if isExternalPath(libPath, projectRoot) {
				externalLibPaths[filepath.ToSlash(libPath)] = true
			}
		}
	}
}
