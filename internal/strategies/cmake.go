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

// CMakeStrategy parses CMakeCache.txt and CMakeLists.txt files to detect
// dependencies declared via find_package(), FetchContent_Declare(), and
// target_link_libraries().
type CMakeStrategy struct{}

func (s *CMakeStrategy) Name() string { return "cmake" }

// reCMakeFindPackage matches find_package(Foo ...) calls
var reCMakeFindPackage = regexp.MustCompile(`(?i)find_package\s*\(\s*([A-Za-z0-9_\-]+)`)

// reCMakeFetchContent matches FetchContent_Declare(foo ...) calls
var reCMakeFetchContent = regexp.MustCompile(`(?i)FetchContent_Declare\s*\(\s*([A-Za-z0-9_\-]+)`)

// reCMakeTargetLink matches target_link_libraries(target ... Foo::Bar ...)
var reCMakeTargetLink = regexp.MustCompile(`(?i)target_link_libraries\s*\([^)]+\)`)

// reCMakeLibToken matches library tokens like Foo::Bar or ${Foo_LIBRARIES}
var reCMakeLibToken = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_]+)::([A-Za-z0-9_]+)`)

// reCMakeCacheDir matches CMakeCache entries like Boost_DIR or OpenSSL_INCLUDE_DIR
var reCMakeCacheDir = regexp.MustCompile(`(?i)^([A-Za-z0-9_]+)(?:_DIR|_INCLUDE_DIR|_INCLUDE_DIRS|_ROOT):(?:PATH|STRING|FILEPATH)\s*=\s*(.+)$`)

// reCMakeCacheLib matches CMakeCache entries like Boost_LIBRARIES
var reCMakeCacheLib = regexp.MustCompile(`(?i)^([A-Za-z0-9_]+)(?:_LIBRARIES|_LIBRARY|_LIB):(?:FILEPATH|STRING)\s*=\s*(.+)$`)

// reCMakeCacheVersion matches CMakeCache version entries
var reCMakeCacheVersion = regexp.MustCompile(`(?i)^([A-Za-z0-9_]+)_VERSION(?:_STRING)?:STRING\s*=\s*(.+)$`)

// reCMakeProjectVersion matches project(Name VERSION x.y.z) in CMakeLists.txt
var reCMakeProjectVersion = regexp.MustCompile(`(?i)project\s*\([^)]*VERSION\s+([\d.]+)`)

// reCMakeGitTag matches GIT_TAG in FetchContent blocks
var reCMakeGitTag = regexp.MustCompile(`(?i)GIT_TAG\s+([^\s)]+)`)

func (s *CMakeStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	seen := map[string]*model.Component{}
	versions := map[string]string{} // library name (lower) -> version

	// First pass: parse CMakeCache.txt for definitive version info
	cacheFiles := []string{
		filepath.Join(projectRoot, "CMakeCache.txt"),
		filepath.Join(projectRoot, "build", "CMakeCache.txt"),
		filepath.Join(projectRoot, "out", "CMakeCache.txt"),
		filepath.Join(projectRoot, "cmake-build-debug", "CMakeCache.txt"),
		filepath.Join(projectRoot, "cmake-build-release", "CMakeCache.txt"),
	}

	for _, cf := range cacheFiles {
		if _, err := os.Stat(cf); err != nil {
			continue
		}
		if verbose {
			fmt.Printf("  [cmake] Parsing CMakeCache.txt: %s\n", cf)
		}
		parseCMakeCache(cf, projectRoot, seen, versions, verbose)
	}

	// Second pass: walk all CMakeLists.txt files
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
		if strings.EqualFold(d.Name(), "CMakeLists.txt") {
			if verbose {
				fmt.Printf("  [cmake] Parsing CMakeLists.txt: %s\n", path)
			}
			parseCMakeLists(path, seen, versions, verbose)
		}
		return nil
	})

	// Apply collected versions
	for name, c := range seen {
		if c.Version == "unknown" {
			if v, ok := versions[strings.ToLower(name)]; ok && v != "" {
				c.Version = v
				fp := fingerprints.MatchLibrary(name)
				if fp != nil {
					c.PURL = fp.PURL + "@" + v
				}
			}
		}
	}

	result := make([]*model.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result, nil
}

func parseCMakeCache(path, projectRoot string, seen map[string]*model.Component, versions map[string]string, verbose bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Version entries
		if m := reCMakeCacheVersion.FindStringSubmatch(line); m != nil {
			libName := strings.ToLower(m[1])
			ver := strings.TrimSpace(m[2])
			if ver != "" && ver != "ver-NOTFOUND" {
				versions[libName] = ver
			}
		}

		// Directory / include path entries
		if m := reCMakeCacheDir.FindStringSubmatch(line); m != nil {
			libPrefix := m[1]
			dirPath := strings.TrimSpace(m[2])
			if dirPath == "" || strings.HasSuffix(dirPath, "-NOTFOUND") {
				continue
			}
			if !isExternalPath(dirPath, projectRoot) {
				continue
			}
			fp := fingerprints.MatchLibrary(libPrefix)
			if fp == nil {
				fp = fingerprints.MatchLibrary(dirPath)
			}
			if fp == nil {
				continue
			}
			addOrUpdate(seen, fp, dirPath, "", "cmake")
		}

		// Library path entries
		if m := reCMakeCacheLib.FindStringSubmatch(line); m != nil {
			libPrefix := m[1]
			libPath := strings.TrimSpace(m[2])
			if libPath == "" || strings.HasSuffix(libPath, "-NOTFOUND") {
				continue
			}
			fp := fingerprints.MatchLibrary(libPrefix)
			if fp == nil {
				fp = fingerprints.MatchLibrary(libPath)
			}
			if fp == nil {
				continue
			}
			addOrUpdate(seen, fp, "", filepath.Base(libPath), "cmake")
		}
	}
}

func parseCMakeLists(path string, seen map[string]*model.Component, versions map[string]string, verbose bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// find_package(Foo ...)
	for _, m := range reCMakeFindPackage.FindAllStringSubmatch(content, -1) {
		pkgName := m[1]
		// Skip CMake built-in modules
		if isCMakeBuiltin(pkgName) {
			continue
		}
		fp := fingerprints.MatchLibrary(pkgName)
		if fp == nil {
			// Create a generic component for unknown packages
			fp = &fingerprints.LibraryFingerprint{
				Name:        strings.ToLower(pkgName),
				PURL:        "pkg:generic/" + strings.ToLower(pkgName),
				Description: "Detected via CMake find_package()",
			}
		}
		addOrUpdate(seen, fp, "", "", "cmake")
	}

	// FetchContent_Declare(foo GIT_REPOSITORY ... GIT_TAG ...)
	// Find all FetchContent blocks
	fetchMatches := reCMakeFetchContent.FindAllStringSubmatchIndex(content, -1)
	for _, loc := range fetchMatches {
		pkgName := content[loc[2]:loc[3]]
		fp := fingerprints.MatchLibrary(pkgName)
		if fp == nil {
			fp = &fingerprints.LibraryFingerprint{
				Name:        strings.ToLower(pkgName),
				PURL:        "pkg:generic/" + strings.ToLower(pkgName),
				Description: "Detected via CMake FetchContent_Declare()",
			}
		}
		// Look for GIT_TAG in the next 500 chars
		end := loc[1] + 500
		if end > len(content) {
			end = len(content)
		}
		block := content[loc[1]:end]
		if tm := reCMakeGitTag.FindStringSubmatch(block); tm != nil {
			tag := tm[1]
			// Clean up tag: v1.2.3 -> 1.2.3
			tag = strings.TrimPrefix(tag, "v")
			versions[strings.ToLower(pkgName)] = tag
		}
		addOrUpdate(seen, fp, "", "", "cmake")
	}

	// target_link_libraries with Foo::Bar namespace tokens
	for _, m := range reCMakeLibToken.FindAllStringSubmatch(content, -1) {
		ns := m[1]
		if isCMakeBuiltin(ns) {
			continue
		}
		fp := fingerprints.MatchLibrary(ns)
		if fp != nil {
			addOrUpdate(seen, fp, "", "", "cmake")
		}
	}
}

func addOrUpdate(seen map[string]*model.Component, fp *fingerprints.LibraryFingerprint, incPath, lib, source string) {
	c, ok := seen[fp.Name]
	if !ok {
		c = &model.Component{
			Name:            fp.Name,
			Version:         "unknown",
			PURL:            fp.PURL,
			DetectionSource: source,
			Description:     fp.Description,
		}
		seen[fp.Name] = c
	}
	if incPath != "" {
		c.IncludePaths = appendUnique(c.IncludePaths, incPath)
	}
	if lib != "" {
		c.LinkLibraries = appendUnique(c.LinkLibraries, lib)
	}
}

// cmakeBuiltins is a set of CMake built-in module names to skip.
var cmakeBuiltins = map[string]bool{
	"Threads": true, "OpenMP": true, "MPI": true, "CUDA": true,
	"CUDAToolkit": true, "Python": true, "Python3": true, "Python2": true,
	"PkgConfig": true, "GNUInstallDirs": true, "CMakePackageConfigHelpers": true,
	"CheckCXXCompilerFlag": true, "CheckCCompilerFlag": true,
	"CheckIncludeFile": true, "CheckIncludeFileCXX": true,
	"CheckFunctionExists": true, "CheckLibraryExists": true,
	"CheckSymbolExists": true, "CheckTypeSize": true,
	"ExternalProject": true, "FetchContent": true,
	"CTest": true, "CPack": true, "InstallRequiredSystemLibraries": true,
	"GenerateExportHeader": true, "WriteCompilerDetectionHeader": true,
}

func isCMakeBuiltin(name string) bool {
	return cmakeBuiltins[name]
}
