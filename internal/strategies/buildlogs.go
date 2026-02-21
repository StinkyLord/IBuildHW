package strategies

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
)

// BuildLogsStrategy parses build system artifacts that contain compiler and
// linker command lines:
//   - CMakeFiles/<target>/link.txt  (CMake writes the exact linker command)
//   - *.tlog files                  (MSBuild tracking logs)
//   - build.ninja                   (Ninja build file)
//   - Makefile                      (GNU Make)
type BuildLogsStrategy struct{}

func (s *BuildLogsStrategy) Name() string { return "build-logs" }

// reLinkTxtLib matches -l<lib> and /DEFAULTLIB:<lib> in link.txt files
var reLinkTxtLib = regexp.MustCompile(`(?i)(?:\s|^)(?:-l([^\s]+)|/DEFAULTLIB:([^\s]+))`)

// reLinkTxtLibPath matches absolute library paths in link.txt
var reLinkTxtLibPath = regexp.MustCompile(`(?i)([A-Za-z]:[\\\/][^\s"]+\.(?:lib|a)|\/[^\s"]+\.(?:lib|a|so(?:\.\d+)*))`)

// reLinkTxtInclude matches -I and /I flags in link.txt / tlog files
var reLinkTxtInclude = regexp.MustCompile(`(?i)(?:\s|^)(?:-I|/I)([^\s]+)`)

// reTlogLibPath matches absolute .lib paths in MSBuild .tlog files
var reTlogLibPath = regexp.MustCompile(`(?i)([A-Za-z]:[\\\/][^\|\r\n"]+\.lib)`)

// reNinjaLib matches -l flags in build.ninja rule lines
var reNinjaLib = regexp.MustCompile(`(?i)\s-l([^\s\\]+)`)

// reMakefileLib matches -l flags in Makefile lines
var reMakefileLib = regexp.MustCompile(`(?i)\s-l([^\s\\]+)`)

func (s *BuildLogsStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	externalIncludes := map[string]bool{}
	externalLibs := map[string]bool{}
	externalLibPaths := map[string]bool{}

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

		name := d.Name()
		lname := strings.ToLower(name)

		switch {
		case lname == "link.txt":
			// CMakeFiles/<target>/link.txt
			parseLinkTxt(path, projectRoot, externalLibs, externalLibPaths, externalIncludes, verbose)

		case strings.HasSuffix(lname, ".tlog"):
			// MSBuild tracking log
			parseTlog(path, projectRoot, externalLibPaths, verbose)

		case lname == "build.ninja":
			parseNinja(path, projectRoot, externalLibs, externalIncludes, verbose)

		case lname == "makefile" || lname == "gnumakefile":
			parseMakefile(path, projectRoot, externalLibs, externalIncludes, verbose)
		}
		return nil
	})

	// Merge all sources into components
	allIncludes := map[string]bool{}
	for k := range externalIncludes {
		allIncludes[k] = true
	}
	for k := range externalLibPaths {
		// Treat the directory of the lib path as an include hint
		allIncludes[filepath.ToSlash(filepath.Dir(k))] = true
	}

	components := buildComponentsFromPaths(allIncludes, externalLibs, s.Name())

	// Also try to match raw lib paths
	for libPath := range externalLibPaths {
		found := false
		for _, c := range components {
			for _, ll := range c.LinkLibraries {
				if strings.EqualFold(ll, filepath.Base(libPath)) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			// Try to match by path
			extra := buildComponentsFromPaths(
				map[string]bool{filepath.ToSlash(libPath): true},
				nil,
				s.Name(),
			)
			components = append(components, extra...)
		}
	}

	return components, nil
}

func parseLinkTxt(path, projectRoot string, libs, libPaths, includes map[string]bool, verbose bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if verbose {
		fmt.Printf("  [build-logs] Parsing link.txt: %s\n", path)
	}
	content := string(data)

	for _, m := range reLinkTxtLib.FindAllStringSubmatch(content, -1) {
		lib := ""
		if len(m) > 1 && m[1] != "" {
			lib = m[1]
		} else if len(m) > 2 && m[2] != "" {
			lib = m[2]
		}
		if lib != "" {
			libs[lib] = true
		}
	}

	for _, m := range reLinkTxtLibPath.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 && isExternalPath(m[1], projectRoot) {
			libPaths[filepath.ToSlash(m[1])] = true
		}
	}

	for _, m := range reLinkTxtInclude.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 && isExternalPath(m[1], projectRoot) {
			includes[filepath.ToSlash(m[1])] = true
		}
	}
}

func parseTlog(path, projectRoot string, libPaths map[string]bool, verbose bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if verbose {
		fmt.Printf("  [build-logs] Parsing tlog: %s\n", path)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, m := range reTlogLibPath.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 && isExternalPath(m[1], projectRoot) {
				libPaths[filepath.ToSlash(m[1])] = true
			}
		}
	}
}

func parseNinja(path, projectRoot string, libs, includes map[string]bool, verbose bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if verbose {
		fmt.Printf("  [build-logs] Parsing build.ninja: %s\n", path)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Link flags
		for _, m := range reNinjaLib.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 {
				libs[m[1]] = true
			}
		}
		// Include flags
		for _, m := range reLinkTxtInclude.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 && isExternalPath(m[1], projectRoot) {
				includes[filepath.ToSlash(m[1])] = true
			}
		}
	}
}

func parseMakefile(path, projectRoot string, libs, includes map[string]bool, verbose bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if verbose {
		fmt.Printf("  [build-logs] Parsing Makefile: %s\n", path)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, m := range reMakefileLib.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 {
				libs[m[1]] = true
			}
		}
		for _, m := range reLinkTxtInclude.FindAllStringSubmatch(line, -1) {
			if len(m) > 1 && isExternalPath(m[1], projectRoot) {
				includes[filepath.ToSlash(m[1])] = true
			}
		}
	}
}
