// Package strategies contains all dependency detection strategies.
package strategies

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/StinkyLord/cpp-sbom-builder/internal/fingerprints"
	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
)

// compileCommand represents one entry in compile_commands.json.
type compileCommand struct {
	Directory string   `json:"directory"`
	Command   string   `json:"command"`
	Arguments []string `json:"arguments"`
	File      string   `json:"file"`
}

// reIncludeFlag matches -I/path or /I/path or -isystem /path compiler flags.
var reIncludeFlag = regexp.MustCompile(`(?i)(?:^|[\s,])(?:-I|/I|-isystem\s+|-imsvc\s*)([^\s,]+)`)

// reLinkFlag matches -l<lib> or /DEFAULTLIB:<lib> linker flags.
var reLinkFlag = regexp.MustCompile(`(?i)(?:^|[\s,])(?:-l([^\s,]+)|/DEFAULTLIB:([^\s,]+))`)

// reLibPathFlag matches -L<path> or /LIBPATH:<path> linker search path flags.
var reLibPathFlag = regexp.MustCompile(`(?i)(?:^|[\s,])(?:-L([^\s,]+)|/LIBPATH:([^\s,]+))`)

// CompileCommandsStrategy scans compile_commands.json for external include paths
// and link flags. This is the primary compiler-level signal.
type CompileCommandsStrategy struct{}

func (s *CompileCommandsStrategy) Name() string { return "compile_commands.json" }

func (s *CompileCommandsStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	// compile_commands.json can live in the project root or in a build subdirectory.
	candidates := []string{
		filepath.Join(projectRoot, "compile_commands.json"),
		filepath.Join(projectRoot, "build", "compile_commands.json"),
		filepath.Join(projectRoot, "out", "compile_commands.json"),
		filepath.Join(projectRoot, "cmake-build-debug", "compile_commands.json"),
		filepath.Join(projectRoot, "cmake-build-release", "compile_commands.json"),
		filepath.Join(projectRoot, ".build", "compile_commands.json"),
	}

	// Also walk up to 3 levels deep looking for compile_commands.json
	found := []string{}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			found = append(found, c)
		}
	}

	// Walk build directories for compile_commands.json
	_ = filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Skip hidden dirs and common non-build dirs
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
		}
		if !d.IsDir() && d.Name() == "compile_commands.json" {
			// Avoid duplicates
			for _, f := range found {
				if f == path {
					return nil
				}
			}
			found = append(found, path)
		}
		return nil
	})

	if len(found) == 0 {
		if verbose {
			fmt.Println("  [compile_commands] No compile_commands.json found")
		}
		return nil, nil
	}

	// Collect all external include paths across all compile_commands.json files
	externalIncludes := map[string]bool{}
	externalLibs := map[string]bool{}

	for _, ccPath := range found {
		if verbose {
			fmt.Printf("  [compile_commands] Parsing %s\n", ccPath)
		}
		data, err := os.ReadFile(ccPath)
		if err != nil {
			continue
		}
		var commands []compileCommand
		if err := json.Unmarshal(data, &commands); err != nil {
			continue
		}

		for _, cmd := range commands {
			// Build a single string to parse from either command or arguments
			cmdStr := cmd.Command
			if cmdStr == "" && len(cmd.Arguments) > 0 {
				cmdStr = strings.Join(cmd.Arguments, " ")
			}

			// Extract -I include paths
			for _, m := range reIncludeFlag.FindAllStringSubmatch(cmdStr, -1) {
				if len(m) > 1 {
					incPath := strings.TrimSpace(m[1])
					if isExternalPath(incPath, projectRoot) {
						externalIncludes[filepath.ToSlash(incPath)] = true
					}
				}
			}

			// Extract -l link libraries
			for _, m := range reLinkFlag.FindAllStringSubmatch(cmdStr, -1) {
				lib := ""
				if len(m) > 1 && m[1] != "" {
					lib = m[1]
				} else if len(m) > 2 && m[2] != "" {
					lib = m[2]
				}
				if lib != "" {
					externalLibs[lib] = true
				}
			}

			// Also parse individual arguments for cleaner extraction
			for _, arg := range cmd.Arguments {
				arg = strings.TrimSpace(arg)
				if strings.HasPrefix(arg, "-I") && len(arg) > 2 {
					incPath := arg[2:]
					if isExternalPath(incPath, projectRoot) {
						externalIncludes[filepath.ToSlash(incPath)] = true
					}
				} else if strings.HasPrefix(arg, "/I") && len(arg) > 2 {
					incPath := arg[2:]
					if isExternalPath(incPath, projectRoot) {
						externalIncludes[filepath.ToSlash(incPath)] = true
					}
				} else if strings.HasPrefix(arg, "-l") && len(arg) > 2 {
					externalLibs[arg[2:]] = true
				}
			}
		}
	}

	return buildComponentsFromPaths(externalIncludes, externalLibs, s.Name()), nil
}

// isExternalPath returns true if the given path is outside the project root.
func isExternalPath(path, projectRoot string) bool {
	if path == "" {
		return false
	}
	// Make both absolute for comparison
	absPath, err := filepath.Abs(path)
	if err != nil {
		// If we can't resolve, treat as external if it doesn't start with a relative marker
		return !strings.HasPrefix(path, ".") && filepath.IsAbs(path)
	}
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return false
	}
	// Normalise separators
	absPath = filepath.ToSlash(strings.ToLower(absPath))
	absRoot = filepath.ToSlash(strings.ToLower(absRoot))
	return !strings.HasPrefix(absPath, absRoot)
}

// buildComponentsFromPaths maps external include paths and link libs to known library fingerprints.
func buildComponentsFromPaths(includes map[string]bool, libs map[string]bool, source string) []*model.Component {
	seen := map[string]*model.Component{}

	addComponent := func(fp *fingerprints.LibraryFingerprint, incPath, lib string) {
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
			// Try to extract version from path (e.g. boost_1_82_0, openssl-3.1.4)
			if v := extractVersionFromPath(incPath); v != "" && c.Version == "unknown" {
				c.Version = v
				c.PURL = fp.PURL + "@" + v
			}
		}
		if lib != "" {
			c.LinkLibraries = appendUnique(c.LinkLibraries, lib)
			if v := extractVersionFromLibName(lib); v != "" && c.Version == "unknown" {
				c.Version = v
				c.PURL = fp.PURL + "@" + v
			}
		}
	}

	for incPath := range includes {
		if fp := fingerprints.MatchLibrary(incPath); fp != nil {
			addComponent(fp, incPath, "")
		}
	}

	for lib := range libs {
		if fp := fingerprints.MatchLibrary(lib); fp != nil {
			addComponent(fp, "", lib)
		}
	}

	result := make([]*model.Component, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result
}

// reVersionInPath matches version strings in paths like boost_1_82_0, openssl-3.1.4, zlib-1.2.11
var reVersionInPath = regexp.MustCompile(`[-_](\d+)[._](\d+)(?:[._](\d+))?`)

func extractVersionFromPath(path string) string {
	// Look for patterns like /boost/1.82.0/ or boost_1_82_0
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		if m := reVersionInPath.FindStringSubmatch(part); m != nil {
			v := m[1] + "." + m[2]
			if m[3] != "" {
				v += "." + m[3]
			}
			return v
		}
	}
	return ""
}

// reVersionInLibName matches MSVC-decorated lib names like boost_system-vc143-mt-x64-1_82.lib
var reVersionInLibName = regexp.MustCompile(`[-_](\d+)[._](\d+)(?:[._](\d+))?(?:\.lib|\.a)?$`)

func extractVersionFromLibName(lib string) string {
	if m := reVersionInLibName.FindStringSubmatch(lib); m != nil {
		v := m[1] + "." + m[2]
		if m[3] != "" {
			v += "." + m[3]
		}
		return v
	}
	return ""
}

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
