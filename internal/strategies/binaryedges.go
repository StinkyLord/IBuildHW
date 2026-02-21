package strategies

// BinaryEdgesStrategy scans compiled binary artifacts (.so, .dll, .lib) to
// extract dependency edges — i.e., which library depends on which other library.
//
// Sources:
//   - ELF shared libraries (.so): DT_NEEDED entries in the dynamic section
//     (Go stdlib: debug/elf)
//   - PE DLLs (.dll): import directory table
//     (Go stdlib: debug/pe)
//   - MSVC static libraries (.lib): /DEFAULTLIB directives embedded in the
//     linker member (parsed as text — no external tool required)
//
// The result is a set of directed edges: parentLibName -> []childLibName.
// These are then mapped to package names via the fingerprint database and
// merged into the dependency tree by the scanner.

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/StinkyLord/cpp-sbom-builder/internal/fingerprints"
	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
)

// BinaryEdgesStrategy implements Strategy.
type BinaryEdgesStrategy struct{}

func (s *BinaryEdgesStrategy) Name() string { return "binary-edges" }

// BinaryEdgeResult holds the components found and the parent→child edges.
type BinaryEdgeResult struct {
	Components []*model.Component
	// Edges maps package name -> list of child package names
	Edges map[string][]string
}

func (s *BinaryEdgesStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	r := s.ScanWithEdges(projectRoot, verbose)
	return r.Components, nil
}

// ScanWithEdges returns both components and the dependency edges.
func (s *BinaryEdgesStrategy) ScanWithEdges(projectRoot string, verbose bool) *BinaryEdgeResult {
	result := &BinaryEdgeResult{
		Edges: map[string][]string{},
	}

	seen := map[string]*model.Component{}

	_ = filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".git") || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		switch ext {
		case ".so":
			// Also match versioned .so files like libssl.so.3
			s.processELF(path, projectRoot, seen, result.Edges, verbose)
		case ".dll":
			s.processPE(path, projectRoot, seen, result.Edges, verbose)
		case ".lib":
			s.processMSVCLib(path, projectRoot, seen, result.Edges, verbose)
		default:
			// Check for versioned .so files (e.g. libssl.so.3.1.4)
			base := d.Name()
			if idx := strings.Index(base, ".so."); idx != -1 {
				s.processELF(path, projectRoot, seen, result.Edges, verbose)
			}
		}
		return nil
	})

	for _, c := range seen {
		result.Components = append(result.Components, c)
	}
	return result
}

// ---- ELF DT_NEEDED ----

func (s *BinaryEdgesStrategy) processELF(
	path, projectRoot string,
	seen map[string]*model.Component,
	edges map[string][]string,
	verbose bool,
) {
	// Only process external libraries (outside project root)
	if !isExternalPath(path, projectRoot) {
		return
	}

	f, err := elf.Open(path)
	if err != nil {
		return // not a valid ELF file
	}
	defer f.Close()

	needed, err := f.DynString(elf.DT_NEEDED)
	if err != nil || len(needed) == 0 {
		return
	}

	if verbose {
		fmt.Printf("  [binary-edges] ELF %s → needs: %v\n", filepath.Base(path), needed)
	}

	// Map this .so file to a package
	parentPkg := libNameToPackage(filepath.Base(path))
	if parentPkg == nil {
		return
	}

	// Ensure parent component exists
	if _, ok := seen[parentPkg.Name]; !ok {
		c := &model.Component{
			Name:            parentPkg.Name,
			Version:         extractVersionFromPath(path),
			PURL:            parentPkg.PURL,
			DetectionSource: s.Name(),
			Description:     parentPkg.Description,
		}
		if c.Version == "" {
			c.Version = "unknown"
		}
		seen[parentPkg.Name] = c
	}

	// Map each needed library to a package and record the edge
	for _, dep := range needed {
		childPkg := libNameToPackage(dep)
		if childPkg == nil {
			continue
		}
		if childPkg.Name == parentPkg.Name {
			continue
		}

		// Ensure child component exists
		if _, ok := seen[childPkg.Name]; !ok {
			c := &model.Component{
				Name:            childPkg.Name,
				Version:         extractVersionFromPath(dep),
				PURL:            childPkg.PURL,
				DetectionSource: s.Name(),
				Description:     childPkg.Description,
			}
			if c.Version == "" {
				c.Version = "unknown"
			}
			seen[childPkg.Name] = c
		}

		edges[parentPkg.Name] = appendUnique(edges[parentPkg.Name], childPkg.Name)
	}
}

// ---- PE Import Table ----

func (s *BinaryEdgesStrategy) processPE(
	path, projectRoot string,
	seen map[string]*model.Component,
	edges map[string][]string,
	verbose bool,
) {
	if !isExternalPath(path, projectRoot) {
		return
	}

	f, err := pe.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	// Collect imported DLL names
	var importedDLLs []string
	switch hdr := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		_ = hdr
		importedDLLs = getPEImports(f)
	case *pe.OptionalHeader64:
		_ = hdr
		importedDLLs = getPEImports(f)
	default:
		importedDLLs = getPEImports(f)
	}

	if len(importedDLLs) == 0 {
		return
	}

	if verbose {
		fmt.Printf("  [binary-edges] PE %s → imports: %v\n", filepath.Base(path), importedDLLs)
	}

	parentPkg := libNameToPackage(filepath.Base(path))
	if parentPkg == nil {
		return
	}

	if _, ok := seen[parentPkg.Name]; !ok {
		c := &model.Component{
			Name:            parentPkg.Name,
			Version:         extractVersionFromPath(path),
			PURL:            parentPkg.PURL,
			DetectionSource: s.Name(),
			Description:     parentPkg.Description,
		}
		if c.Version == "" {
			c.Version = "unknown"
		}
		seen[parentPkg.Name] = c
	}

	for _, dll := range importedDLLs {
		childPkg := libNameToPackage(dll)
		if childPkg == nil || childPkg.Name == parentPkg.Name {
			continue
		}
		if _, ok := seen[childPkg.Name]; !ok {
			c := &model.Component{
				Name:            childPkg.Name,
				Version:         "unknown",
				PURL:            childPkg.PURL,
				DetectionSource: s.Name(),
				Description:     childPkg.Description,
			}
			seen[childPkg.Name] = c
		}
		edges[parentPkg.Name] = appendUnique(edges[parentPkg.Name], childPkg.Name)
	}
}

func getPEImports(f *pe.File) []string {
	imports, err := f.ImportedLibraries()
	if err != nil {
		return nil
	}
	return imports
}

// ---- MSVC .lib DEFAULTLIB directives ----

// reMSVCDefaultLib matches /DEFAULTLIB:"name" or /DEFAULTLIB:name in .lib files
var reMSVCDefaultLib = regexp.MustCompile(`(?i)/DEFAULTLIB[:\s]+"?([A-Za-z0-9_\-\.]+)"?`)

func (s *BinaryEdgesStrategy) processMSVCLib(
	path, projectRoot string,
	seen map[string]*model.Component,
	edges map[string][]string,
	verbose bool,
) {
	if !isExternalPath(path, projectRoot) {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// MSVC .lib files are AR archives. The linker member (first member) contains
	// the /DEFAULTLIB directives as ASCII text. We scan the whole file as text
	// since the directives are always ASCII and easy to find.
	// We limit to the first 64KB to avoid reading huge static libraries fully.
	limit := len(data)
	if limit > 65536 {
		limit = 65536
	}
	chunk := data[:limit]

	// Only process if it looks like an MSVC lib (starts with "!<arch>" or has DEFAULTLIB)
	if !bytes.Contains(chunk, []byte("!<arch>")) && !bytes.Contains(chunk, []byte("DEFAULTLIB")) {
		return
	}

	parentPkg := libNameToPackage(filepath.Base(path))
	if parentPkg == nil {
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(chunk))
	scanner.Buffer(make([]byte, 4096), 4096)
	var deps []string
	for scanner.Scan() {
		line := scanner.Text()
		for _, m := range reMSVCDefaultLib.FindAllStringSubmatch(line, -1) {
			depName := m[1]
			// Skip CRT libraries
			if isCRTLib(depName) {
				continue
			}
			childPkg := libNameToPackage(depName)
			if childPkg != nil && childPkg.Name != parentPkg.Name {
				deps = append(deps, childPkg.Name)
			}
		}
	}

	if len(deps) == 0 {
		return
	}

	if verbose {
		fmt.Printf("  [binary-edges] MSVC lib %s → DEFAULTLIB: %v\n", filepath.Base(path), deps)
	}

	if _, ok := seen[parentPkg.Name]; !ok {
		c := &model.Component{
			Name:            parentPkg.Name,
			Version:         extractVersionFromPath(path),
			PURL:            parentPkg.PURL,
			DetectionSource: s.Name(),
			Description:     parentPkg.Description,
		}
		if c.Version == "" {
			c.Version = "unknown"
		}
		seen[parentPkg.Name] = c
	}

	for _, childName := range deps {
		if _, ok := seen[childName]; !ok {
			fp := fingerprints.MatchLibrary(childName)
			if fp != nil {
				seen[childName] = &model.Component{
					Name:            fp.Name,
					Version:         "unknown",
					PURL:            fp.PURL,
					DetectionSource: s.Name(),
					Description:     fp.Description,
				}
			}
		}
		edges[parentPkg.Name] = appendUnique(edges[parentPkg.Name], childName)
	}
}

// ---- helpers ----

// libNameToPackage maps a library filename (e.g. "libssl.so.3", "ssl.dll", "libssl.a")
// to a fingerprint package entry.
func libNameToPackage(libName string) *fingerprints.LibraryFingerprint {
	// Strip versioned suffix: libssl.so.3.1.4 -> libssl.so -> libssl
	base := strings.ToLower(libName)

	// Remove .so.X.Y.Z suffix
	if idx := strings.Index(base, ".so"); idx != -1 {
		base = base[:idx]
	}
	// Remove common prefixes and suffixes
	base = strings.TrimPrefix(base, "lib")
	base = strings.TrimSuffix(base, ".dll")
	base = strings.TrimSuffix(base, ".lib")
	base = strings.TrimSuffix(base, ".a")
	base = strings.TrimSuffix(base, ".dylib")

	// Try the cleaned name
	if fp := fingerprints.MatchLibrary(base); fp != nil {
		return fp
	}
	// Try the original name
	if fp := fingerprints.MatchLibrary(libName); fp != nil {
		return fp
	}
	return nil
}

// isCRTLib returns true for well-known MSVC C runtime library names that
// should not be treated as third-party dependencies.
var crtLibs = map[string]bool{
	"libcmt": true, "libcmtd": true, "msvcrt": true, "msvcrtd": true,
	"vcruntime": true, "vcruntimed": true, "ucrt": true, "ucrtd": true,
	"oldnames": true, "kernel32": true, "user32": true, "advapi32": true,
	"shell32": true, "ole32": true, "oleaut32": true, "uuid": true,
	"comdlg32": true, "winspool": true, "gdi32": true, "ws2_32": true,
	"ntdll": true, "ntoskrnl": true,
}

func isCRTLib(name string) bool {
	return crtLibs[strings.ToLower(name)]
}
