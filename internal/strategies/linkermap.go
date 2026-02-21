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
//
// NOTE: Cross-compile map files (e.g. ARM GCC on Windows) use mixed separators:
//
//	LOAD c:/path/to/nofp\libgcc.a
//
// The path ends with a backslash-separated filename, so we must allow [^\s]+ to
// match backslashes inside the path.
var reMapLibEntry = regexp.MustCompile(`(?i)(?:LOAD\s+|^\s*)([A-Za-z]:[\\\/][^\s]+\.(?:lib|a|so(?:\.\d+)*)|\/[^\s]+\.(?:lib|a|so(?:\.\d+)*))`)

// reMSVCLibLine matches lines in MSVC map files that reference .lib files
var reMSVCLibLine = regexp.MustCompile(`(?i)([A-Za-z]:[\\\/][^\s"]+\.lib|[^\s"]+\.lib)`)

// reSatisfyRef matches the GNU linker "satisfy reference" lines (single-line format):
//
//	/path/to/libchild.so    (/path/to/libparent.so(symbol))
//	/path/to/libchild.a(obj.o)    (libparent.so(symbol))
var reSatisfyRef = regexp.MustCompile(`^\s*([^\s(]+(?:\.(?:so|a|lib)(?:\.\d+)*)?)(?:\([^)]*\))?\s+\(([^\s(]+(?:\.(?:so|a|lib)(?:\.\d+)*)?)`)

// reSatisfyChildLine matches the first line of a two-line satisfy entry (GNU ARM format):
//
//	c:/path/to\libgcc.a(_arm_addsubsf3.o)
//
// Captures the library path (everything up to the opening paren of the object member).
var reSatisfyChildLine = regexp.MustCompile(`(?i)^([A-Za-z]:[\\\/][^\s(]+\.(?:lib|a|so(?:\.\d+)*))\(`)

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

	// Two-line satisfy format (GNU ARM cross-compile):
	//   Line 1 (child):  c:/path/to\libgcc.a(_arm_addsubsf3.o)
	//   Line 2 (parent): <whitespace>build/vddcheck.o (__aeabi_fsub)
	// We remember the child path from line 1 and pair it with the parent on line 2.
	pendingSatisfyChild := ""

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Detect the GNU "Archive member included to satisfy reference" section header
		if strings.Contains(line, "Archive member included") && strings.Contains(line, "satisfy") {
			inSatisfySection = true
			pendingSatisfyChild = ""
			continue
		}

		if inSatisfySection {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				// blank line — stay in section
				continue
			}

			// ── Two-line format (GNU ARM cross-compile) ──────────────────────────
			// Line 1: the child library path followed by (object.o)
			//   c:/path/to\libgcc.a(_arm_addsubsf3.o)
			if pendingSatisfyChild == "" {
				if m := reSatisfyChildLine.FindStringSubmatch(line); m != nil {
					pendingSatisfyChild = filepath.ToSlash(m[1])
					// Also record the child as an external lib path
					if isExternalLibPath(pendingSatisfyChild, projectRoot) {
						externalLibPaths[pendingSatisfyChild] = true
					}
					continue
				}
			} else {
				// Line 2: the parent (requester) — indented, e.g.:
				//   "                              build/vddcheck.o (__aeabi_fsub)"
				// or another library path (lib-to-lib dependency):
				//   "                              c:/path/to\libgcc.a(_aeabi_uldivmod.o) (__udivmoddi4)"
				childPath := pendingSatisfyChild
				pendingSatisfyChild = ""

				// Extract the parent path from the indented line.
				// It may be a project-local file (build/foo.o) or another library.
				parentPath := ""
				if pm := reSatisfyChildLine.FindStringSubmatch(trimmed); pm != nil {
					// Parent is also an external library
					parentPath = filepath.ToSlash(pm[1])
					if isExternalLibPath(parentPath, projectRoot) {
						externalLibPaths[parentPath] = true
					}
				}
				// else: parent is a local object file — we still record the child

				// Record edge if both are known packages
				childPkg := libNameToPackage(filepath.Base(childPath))
				if parentPath != "" {
					parentPkg := libNameToPackage(filepath.Base(parentPath))
					if childPkg != nil && parentPkg != nil && childPkg.Name != parentPkg.Name {
						if verbose {
							fmt.Printf("  [linker-map] edge: %s → %s (satisfy reference)\n",
								parentPkg.Name, childPkg.Name)
						}
						edges[parentPkg.Name] = appendUnique(edges[parentPkg.Name], childPkg.Name)
					}
				}
				continue
			}

			// ── Single-line format (standard GNU ld) ─────────────────────────────
			// /path/to/libchild.so    (/path/to/libparent.so(symbol))
			if m := reSatisfyRef.FindStringSubmatch(line); m != nil {
				childPath := strings.TrimSpace(m[1])
				parentPath := strings.TrimSpace(m[2])

				if isExternalLibPath(childPath, projectRoot) {
					externalLibPaths[filepath.ToSlash(childPath)] = true
				}
				if isExternalLibPath(parentPath, projectRoot) {
					externalLibPaths[filepath.ToSlash(parentPath)] = true
				}

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
			if !strings.HasPrefix(trimmed, "/") && !strings.Contains(trimmed, ":\\") && !strings.Contains(trimmed, ":/") {
				inSatisfySection = false
				pendingSatisfyChild = ""
			}
		}

		// Always collect library paths from LOAD lines and other references
		if m := reMapLibEntry.FindStringSubmatch(line); m != nil {
			libPath := m[1]
			if isExternalLibPath(libPath, projectRoot) {
				externalLibPaths[filepath.ToSlash(libPath)] = true
			}
		}
		for _, m := range reMSVCLibLine.FindAllStringSubmatch(line, -1) {
			libPath := m[1]
			if isExternalLibPath(libPath, projectRoot) {
				externalLibPaths[filepath.ToSlash(libPath)] = true
			}
		}
	}
}

// isExternalLibPath returns true if the given library path is outside the project root.
// Unlike isExternalPath (which uses filepath.Abs and resolves ".." segments), this
// function handles cross-compile paths that contain ".." and mixed separators, e.g.:
//
//	c:/siliconlabs/.../bin/../lib/gcc/arm-none-eabi/10.3.1/../../../../arm-none-eabi/lib/...
//
// For such paths we simply check whether the path is absolute and does NOT start with
// the project root (after normalising separators and case).
func isExternalLibPath(path, projectRoot string) bool {
	if path == "" {
		return false
	}
	// Normalise to forward slashes and lowercase for comparison
	normPath := strings.ToLower(filepath.ToSlash(path))
	normRoot := strings.ToLower(filepath.ToSlash(projectRoot))
	// Ensure root ends with slash for prefix matching
	if !strings.HasSuffix(normRoot, "/") {
		normRoot += "/"
	}

	// If the path is absolute (starts with drive letter or /) and does not
	// start with the project root, it is external.
	isAbs := filepath.IsAbs(path) ||
		(len(path) >= 3 && path[1] == ':' && (path[2] == '/' || path[2] == '\\'))
	if !isAbs {
		return false
	}
	return !strings.HasPrefix(normPath, normRoot)
}
