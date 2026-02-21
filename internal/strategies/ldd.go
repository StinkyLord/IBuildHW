// Package strategies — LddStrategy
//
// Parses the ldd-results.json file produced by docker-entrypoint.sh when
// --ldd is passed. That file contains the output of `ldd <library>` for every
// .so file found in the project, giving us the full transitive runtime
// dependency tree.
//
// ldd output format:
//
//	libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x7f...)
//	libcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3 (0x7f...)
//	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x7f...)
//
// This strategy is Linux-only and is designed to run inside the Docker image.
// On non-Linux hosts it is a no-op (returns empty results).
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

// ─────────────────────────────────────────────────────────────────────────────
// JSON structure for ldd-results.json
// ─────────────────────────────────────────────────────────────────────────────

type lddResultsFile struct {
	Results []lddLibraryEntry `json:"results"`
}

type lddLibraryEntry struct {
	Library string        `json:"library"` // path to the .so file
	Deps    []lddDepEntry `json:"deps"`
}

type lddDepEntry struct {
	Name string `json:"name"` // e.g. "libssl.so.3"
	Path string `json:"path"` // e.g. "/lib/x86_64-linux-gnu/libssl.so.3"
}

// ─────────────────────────────────────────────────────────────────────────────
// LddStrategy
// ─────────────────────────────────────────────────────────────────────────────

// LddStrategy reads the ldd-results.json file written by docker-entrypoint.sh
// and extracts runtime dependency edges from it.
//
// It is activated by the --ldd flag. The entrypoint script sets the
// SBOM_LDD_RESULTS environment variable to the path of the JSON file.
type LddStrategy struct{}

func (s *LddStrategy) Name() string { return "ldd" }

// Scan implements the Strategy interface.
func (s *LddStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	result := s.ScanWithEdges(projectRoot, verbose)
	return result.Components, nil
}

// LddScanResult holds components and dependency edges from ldd output.
type LddScanResult struct {
	Components []*model.Component
	// Edges maps package name → list of child package names
	Edges map[string][]string
}

// ScanWithEdges returns both components and the dependency edges.
func (s *LddStrategy) ScanWithEdges(projectRoot string, verbose bool) *LddScanResult {
	result := &LddScanResult{
		Edges: map[string][]string{},
	}

	// Find the ldd-results.json file.
	// Priority:
	//   1. SBOM_LDD_RESULTS env var (set by docker-entrypoint.sh)
	//   2. <projectRoot>/ldd-results.json (user pre-generated)
	//   3. <projectRoot>/build/ldd-results.json
	lddPath := os.Getenv("SBOM_LDD_RESULTS")
	if lddPath == "" {
		candidates := []string{
			filepath.Join(projectRoot, "ldd-results.json"),
			filepath.Join(projectRoot, "build", "ldd-results.json"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				lddPath = c
				break
			}
		}
	}

	if lddPath == "" {
		if verbose {
			fmt.Println("  [ldd] No ldd-results.json found — skipping (use --ldd inside Docker to generate)")
		}
		return result
	}

	data, err := os.ReadFile(lddPath)
	if err != nil {
		if verbose {
			fmt.Printf("  [ldd] Cannot read %s: %v\n", lddPath, err)
		}
		return result
	}

	if verbose {
		fmt.Printf("  [ldd] Parsing %s\n", lddPath)
	}

	var lddFile lddResultsFile
	if err := json.Unmarshal(data, &lddFile); err != nil {
		if verbose {
			fmt.Printf("  [ldd] JSON parse error: %v\n", err)
		}
		return result
	}

	seen := map[string]*model.Component{}

	for _, entry := range lddFile.Results {
		// Map the parent .so to a package
		parentPkg := libNameToPackage(filepath.Base(entry.Library))
		if parentPkg == nil {
			continue
		}

		// Ensure parent component exists
		if _, ok := seen[parentPkg.Name]; !ok {
			c := &model.Component{
				Name:            parentPkg.Name,
				Version:         extractVersionFromPath(entry.Library),
				PURL:            parentPkg.PURL,
				DetectionSource: s.Name(),
				Description:     parentPkg.Description,
			}
			if c.Version == "" {
				c.Version = "unknown"
			}
			seen[parentPkg.Name] = c
		}

		for _, dep := range entry.Deps {
			// Skip system/libc libraries
			if isSystemLib(dep.Name) {
				continue
			}

			childPkg := libNameToPackage(dep.Name)
			if childPkg == nil {
				// Try matching by path
				if dep.Path != "" {
					childPkg = libNameToPackage(filepath.Base(dep.Path))
				}
			}
			if childPkg == nil || childPkg.Name == parentPkg.Name {
				continue
			}

			// Ensure child component exists
			if _, ok := seen[childPkg.Name]; !ok {
				ver := extractVersionFromPath(dep.Path)
				if ver == "" {
					ver = extractVersionFromPath(dep.Name)
				}
				if ver == "" {
					ver = "unknown"
				}
				c := &model.Component{
					Name:            childPkg.Name,
					Version:         ver,
					PURL:            childPkg.PURL,
					DetectionSource: s.Name(),
					Description:     childPkg.Description,
				}
				seen[childPkg.Name] = c
			}

			// Record the edge: parent depends on child
			result.Edges[parentPkg.Name] = appendUnique(result.Edges[parentPkg.Name], childPkg.Name)

			if verbose {
				fmt.Printf("  [ldd] edge: %s → %s\n", parentPkg.Name, childPkg.Name)
			}
		}
	}

	for _, c := range seen {
		result.Components = append(result.Components, c)
	}

	if verbose {
		fmt.Printf("  [ldd] Found %d component(s) from ldd output\n", len(result.Components))
	}

	return result
}

// isSystemLib returns true for well-known system/libc libraries that should
// not be reported as third-party dependencies.
var systemLibPrefixes = []string{
	"libc.so", "libm.so", "libdl.so", "libpthread.so", "librt.so",
	"libstdc++.so", "libgcc_s.so", "ld-linux", "ld-musl",
	"libgomp.so", "libquadmath.so", "libgfortran.so",
	"linux-vdso.so", "linux-gate.so",
	"libz.so", // zlib is sometimes a system lib — fingerprint DB handles it
	"libutil.so", "libresolv.so", "libnss", "libnsl.so",
}

func isSystemLib(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range systemLibPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// CMakeConfigureStrategy
//
// Reads compile_commands.json and link.txt files generated by a cmake
// configure-only step (cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON).
//
// The link.txt files contain the full linker command line that cmake would
// pass to the linker — including all -l flags and library paths. This is the
// closest equivalent to a linker MAP file that we can produce without actually
// compiling the project.
//
// This strategy is activated by the --cmake-configure flag. The entrypoint
// script sets SBOM_EXTRA_BUILD_DIR to the cmake build directory.
// ─────────────────────────────────────────────────────────────────────────────

// CMakeConfigureStrategy reads artifacts from a cmake configure-only step.
type CMakeConfigureStrategy struct{}

func (s *CMakeConfigureStrategy) Name() string { return "cmake-configure" }

// Scan implements the Strategy interface.
// It delegates to the existing CompileCommandsStrategy and BuildLogsStrategy,
// but pointed at the cmake build directory set by the entrypoint.
func (s *CMakeConfigureStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	// Find the cmake build directory
	buildDir := os.Getenv("SBOM_EXTRA_BUILD_DIR")
	if buildDir == "" {
		// Look for common cmake build directory names
		candidates := []string{
			filepath.Join(projectRoot, "build"),
			filepath.Join(projectRoot, "cmake-build"),
			filepath.Join(projectRoot, "cmake-build-release"),
			filepath.Join(projectRoot, "cmake-build-debug"),
			filepath.Join(projectRoot, "_build"),
			filepath.Join(projectRoot, "out"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(filepath.Join(c, "compile_commands.json")); err == nil {
				buildDir = c
				break
			}
		}
	}

	if buildDir == "" {
		if verbose {
			fmt.Println("  [cmake-configure] No cmake build directory found — skipping")
			fmt.Println("  [cmake-configure] Use --cmake-configure inside Docker to auto-generate")
		}
		return nil, nil
	}

	if verbose {
		fmt.Printf("  [cmake-configure] Using cmake build dir: %s\n", buildDir)
	}

	seen := map[string]*model.Component{}

	// 1. Parse compile_commands.json from the build dir
	ccPath := filepath.Join(buildDir, "compile_commands.json")
	if _, err := os.Stat(ccPath); err == nil {
		if verbose {
			fmt.Printf("  [cmake-configure] Parsing compile_commands.json from %s\n", buildDir)
		}
		ccStrat := &CompileCommandsStrategy{}
		comps, err := ccStrat.Scan(buildDir, verbose)
		if err == nil {
			for _, c := range comps {
				c.DetectionSource = s.Name()
				key := strings.ToLower(c.Name)
				if _, ok := seen[key]; !ok {
					seen[key] = c
				}
			}
		}
	}

	// 2. Parse link.txt files from CMakeFiles/ subdirectories
	// These contain the full linker command line — equivalent to a MAP file's
	// library list. Example content:
	//   /usr/bin/c++ -O3 -DNDEBUG CMakeFiles/myapp.dir/main.cpp.o
	//   -o myapp
	//   /usr/local/lib/libboost_system.a
	//   /usr/lib/x86_64-linux-gnu/libssl.so.3
	//   -lz -lpthread
	linkTxtCount := 0
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() != "link.txt" {
			return nil
		}
		linkTxtCount++
		if verbose {
			fmt.Printf("  [cmake-configure] Parsing link.txt: %s\n", path)
		}
		s.parseLinkTxt(path, projectRoot, seen, verbose)
		return nil
	})

	if verbose && linkTxtCount > 0 {
		fmt.Printf("  [cmake-configure] Parsed %d link.txt file(s) (MAP equivalent)\n", linkTxtCount)
	}

	result := make([]*model.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result, nil
}

// parseLinkTxt parses a CMakeFiles/*/link.txt file and extracts library
// references. These files contain the full linker command line.
func (s *CMakeConfigureStrategy) parseLinkTxt(
	path, projectRoot string,
	seen map[string]*model.Component,
	verbose bool,
) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// link.txt is a single long line (or a few lines) with the full linker command.
	// Split on whitespace to get individual tokens.
	content := string(data)
	tokens := strings.Fields(content)

	for i, token := range tokens {
		var libPath string

		switch {
		// Absolute path to a library: /usr/lib/libssl.so.3 or /usr/lib/libssl.a
		case strings.HasPrefix(token, "/") &&
			(strings.Contains(token, ".so") || strings.HasSuffix(token, ".a") || strings.HasSuffix(token, ".lib")):
			libPath = token

		// -l flag: -lssl, -lboost_system
		case strings.HasPrefix(token, "-l") && len(token) > 2:
			libName := token[2:]
			// Try to match the lib name directly
			fp := fingerprints.MatchLibrary(libName)
			if fp == nil {
				fp = fingerprints.MatchLibrary("lib" + libName)
			}
			if fp != nil {
				key := strings.ToLower(fp.Name)
				if _, ok := seen[key]; !ok {
					seen[key] = &model.Component{
						Name:            fp.Name,
						Version:         "unknown",
						PURL:            fp.PURL,
						DetectionSource: s.Name(),
						Description:     fp.Description,
						LinkLibraries:   []string{libName},
					}
					if verbose {
						fmt.Printf("  [cmake-configure] -l flag: %s → %s\n", libName, fp.Name)
					}
				} else {
					seen[key].LinkLibraries = appendUnique(seen[key].LinkLibraries, libName)
				}
			}
			continue

		// -L flag followed by a path: -L/usr/local/lib
		case strings.HasPrefix(token, "-L") && len(token) > 2:
			// Record the library search path for context but don't create a component
			continue

		// Windows-style: C:\path\to\lib.lib
		case len(token) > 2 && token[1] == ':' &&
			(strings.HasSuffix(strings.ToLower(token), ".lib") || strings.HasSuffix(strings.ToLower(token), ".dll")):
			libPath = token

		default:
			_ = i
			continue
		}

		if libPath == "" {
			continue
		}

		// Skip project-internal paths
		if isInternalPath(libPath, projectRoot) {
			continue
		}

		fp := fingerprints.MatchLibrary(libPath)
		if fp == nil {
			fp = fingerprints.MatchLibrary(filepath.Base(libPath))
		}
		if fp == nil {
			continue
		}

		key := strings.ToLower(fp.Name)
		if _, ok := seen[key]; !ok {
			ver := extractVersionFromPath(libPath)
			if ver == "" {
				ver = extractVersionFromLibName(filepath.Base(libPath))
			}
			if ver == "" {
				ver = "unknown"
			}
			seen[key] = &model.Component{
				Name:            fp.Name,
				Version:         ver,
				PURL:            fp.PURL + "@" + ver,
				DetectionSource: s.Name(),
				Description:     fp.Description,
				LinkLibraries:   []string{filepath.Base(libPath)},
			}
			if verbose {
				fmt.Printf("  [cmake-configure] link.txt lib: %s → %s@%s\n", filepath.Base(libPath), fp.Name, ver)
			}
		} else {
			seen[key].LinkLibraries = appendUnique(seen[key].LinkLibraries, filepath.Base(libPath))
		}
	}
}

// isInternalPath returns true if the path is inside the project root.
func isInternalPath(path, projectRoot string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return false
	}
	return strings.HasPrefix(absPath, absRoot)
}
