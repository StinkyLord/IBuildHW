package strategies

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/StinkyLord/cpp-sbom-builder/internal/fingerprints"
	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
)

// ConanStrategy parses Conan package manager files:
//   - conan.lock (v1 and v2 formats)
//   - conanfile.txt
//   - conanfile.py
type ConanStrategy struct{}

func (s *ConanStrategy) Name() string { return "conan" }

// ---- conan.lock v1 JSON structures ----

type conanLockV1 struct {
	GraphLock struct {
		Nodes map[string]conanLockV1Node `json:"nodes"`
	} `json:"graph_lock"`
}

type conanLockV1Node struct {
	Ref      string   `json:"ref"` // e.g. "boost/1.82.0#abc123"
	Package  string   `json:"package_id"`
	Requires []string `json:"requires"` // indices of dependency nodes, e.g. ["2", "3"]
}

// reConanRef matches Conan package references like "boost/1.82.0" or "openssl/3.1.4@conan/stable#rev"
// Groups: 1=name, 2=version, 3=@user/channel (optional), 4=#revision (optional)
// Revision may be a hex hash (e.g. deadbeef) or an alphanumeric string (e.g. rev001).
var reConanRef = regexp.MustCompile(`^([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^\s#]*)?(?:#([A-Za-z0-9\-_]+))?$`)

// reConanfileTxtRequires matches dependency lines in conanfile.txt sections.
// Captures: 1=name, 2=version, 3=@user/channel (optional), 4=#revision (optional)
var reConanfileTxtRequires = regexp.MustCompile(`^\s*([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^\s#]*)?(?:#([A-Za-z0-9\-_]+))?`)

// reConanfilePyRequires matches self.requires(...) and self.build_requires(...) calls.
// Captures: 1=name, 2=version, 3=@user/channel (optional), 4=#revision (optional)
var reConanfilePyRequires = regexp.MustCompile(`(?:self\.requires|self\.build_requires)\s*\(\s*["']([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^#"']*)?(?:#([A-Za-z0-9\-_]+))?[^"']*["']`)

// reConanfilePyPythonRequires matches python_requires = "name/version..." in conanfile.py
var reConanfilePyPythonRequires = regexp.MustCompile(`python_requires\s*=\s*["']([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^#"']*)?(?:#([A-Za-z0-9\-_]+))?[^"']*["']`)

// ConanScanResult extends the basic component list with graph edge information.
type ConanScanResult struct {
	Components []*model.Component
	// DirectNames is the set of package names declared directly in conanfile.txt/py
	DirectNames map[string]bool
	// Edges maps parent package name -> list of child package names
	Edges map[string][]string
}

func (s *ConanStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	result := s.ScanWithGraph(projectRoot, verbose)
	return result.Components, nil
}

// ScanWithGraph returns the full graph information including direct/transitive edges.
func (s *ConanStrategy) ScanWithGraph(projectRoot string, verbose bool) *ConanScanResult {
	result := &ConanScanResult{
		DirectNames: map[string]bool{},
		Edges:       map[string][]string{},
	}

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
		case "conan.lock":
			if verbose {
				fmt.Printf("  [conan] Parsing conan.lock: %s\n", path)
			}
			lockResult := parseConanLockWithGraph(path)
			result.Components = append(result.Components, lockResult.Components...)
			for k, v := range lockResult.DirectNames {
				result.DirectNames[k] = v
			}
			for k, v := range lockResult.Edges {
				result.Edges[k] = append(result.Edges[k], v...)
			}

		case "conanfile.txt":
			if verbose {
				fmt.Printf("  [conan] Parsing conanfile.txt: %s\n", path)
			}
			comps, directNames := parseConanfileTxtWithDirect(path)
			result.Components = append(result.Components, comps...)
			for k, v := range directNames {
				result.DirectNames[k] = v
			}

		case "conanfile.py":
			if verbose {
				fmt.Printf("  [conan] Parsing conanfile.py: %s\n", path)
			}
			comps, directNames := parseConanfilePyWithDirect(path)
			result.Components = append(result.Components, comps...)
			for k, v := range directNames {
				result.DirectNames[k] = v
			}
		}
		return nil
	})

	return result
}

// lockGraphResult holds the parsed graph from a conan.lock file.
type lockGraphResult struct {
	Components  []*model.Component
	DirectNames map[string]bool
	Edges       map[string][]string
}

func parseConanLockWithGraph(path string) *lockGraphResult {
	data, err := os.ReadFile(path)
	if err != nil {
		return &lockGraphResult{DirectNames: map[string]bool{}, Edges: map[string][]string{}}
	}

	result := &lockGraphResult{
		DirectNames: map[string]bool{},
		Edges:       map[string][]string{},
	}

	// Try v1 format: has graph_lock.nodes map
	var v1 conanLockV1
	if err := json.Unmarshal(data, &v1); err == nil && len(v1.GraphLock.Nodes) > 0 {
		nodeNames := map[string]string{} // node index -> package name

		// First pass: collect all node names
		for idx, node := range v1.GraphLock.Nodes {
			if node.Ref == "" {
				continue
			}
			c := conanRefToComponent(node.Ref, "conan")
			if c == nil {
				continue
			}
			nodeNames[idx] = c.Name
			result.Components = append(result.Components, c)
		}

		// Second pass: build edges. Node "0" is the project root.
		for idx, node := range v1.GraphLock.Nodes {
			parentName := nodeNames[idx]
			if parentName == "" {
				continue
			}
			for _, reqIdx := range node.Requires {
				// reqIdx may be "2" or "2#revision"
				reqIdx = strings.SplitN(reqIdx, "#", 2)[0]
				childName := nodeNames[reqIdx]
				if childName != "" && childName != parentName {
					result.Edges[parentName] = appendUnique(result.Edges[parentName], childName)
				}
			}
			// Node "0" is the project root — its requires are the direct deps
			if idx == "0" {
				for _, reqIdx := range node.Requires {
					reqIdx = strings.SplitN(reqIdx, "#", 2)[0]
					if childName := nodeNames[reqIdx]; childName != "" {
						result.DirectNames[childName] = true
					}
				}
			}
		}
		return result
	}

	// Try v2 format: flat JSON with "requires" / "build_requires" arrays at top level
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		for _, key := range []string{"requires", "build_requires"} {
			if reqRaw, ok := raw[key]; ok {
				var refs []string
				if err := json.Unmarshal(reqRaw, &refs); err == nil {
					for _, ref := range refs {
						c := conanRefToComponent(ref, "conan")
						if c != nil {
							result.Components = append(result.Components, c)
							result.DirectNames[c.Name] = true
						}
					}
				}
			}
		}
	}

	return result
}

func parseConanfileTxtWithDirect(path string) ([]*model.Component, map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var components []*model.Component
	directNames := map[string]bool{}

	// Track which section we're in.
	// Both [requires] and [build_requires] contain direct dependencies.
	type sectionKind int
	const (
		sectionNone          sectionKind = iota
		sectionRequires                  // [requires]
		sectionBuildRequires             // [build_requires]
	)
	currentSection := sectionNone

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			lower := strings.ToLower(line)
			switch lower {
			case "[requires]":
				currentSection = sectionRequires
			case "[build_requires]":
				currentSection = sectionBuildRequires
			default:
				currentSection = sectionNone
			}
			continue
		}
		if currentSection == sectionNone {
			continue
		}

		// m[1]=name, m[2]=version, m[3]=@user/channel, m[4]=#revision
		if m := reConanfileTxtRequires.FindStringSubmatch(line); m != nil {
			channel := strings.TrimPrefix(m[3], "@")
			revision := m[4]
			c := makeConanComponentFull(m[1], m[2], channel, revision, "conan")
			components = append(components, c)
			directNames[c.Name] = true
		}
	}
	return components, directNames
}

func parseConanfilePyWithDirect(path string) ([]*model.Component, map[string]bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	content := string(data)

	var components []*model.Component
	directNames := map[string]bool{}

	// self.requires(...) and self.build_requires(...)
	// m[1]=name, m[2]=version, m[3]=@user/channel, m[4]=#revision
	for _, m := range reConanfilePyRequires.FindAllStringSubmatch(content, -1) {
		channel := strings.TrimPrefix(m[3], "@")
		revision := m[4]
		c := makeConanComponentFull(m[1], m[2], channel, revision, "conan")
		components = append(components, c)
		directNames[c.Name] = true
	}

	// python_requires = "name/version@channel#rev"
	for _, m := range reConanfilePyPythonRequires.FindAllStringSubmatch(content, -1) {
		channel := strings.TrimPrefix(m[3], "@")
		revision := m[4]
		c := makeConanComponentFull(m[1], m[2], channel, revision, "conan")
		components = append(components, c)
		directNames[c.Name] = true
	}

	// requires = ["foo/1.0", ...] list syntax
	reList := regexp.MustCompile(`(?i)(?:^|\s)requires\s*=\s*\[([^\]]+)\]`)
	if lm := reList.FindStringSubmatch(content); lm != nil {
		reItem := regexp.MustCompile(`["']([A-Za-z0-9_\-\.]+)/([A-Za-z0-9_\-\.]+)(@[^#"']*)?(?:#([a-f0-9\-_]+))?[^"']*["']`)
		for _, im := range reItem.FindAllStringSubmatch(lm[1], -1) {
			channel := strings.TrimPrefix(im[3], "@")
			revision := im[4]
			c := makeConanComponentFull(im[1], im[2], channel, revision, "conan")
			components = append(components, c)
			directNames[c.Name] = true
		}
	}

	return components, directNames
}

// conanRefToComponent parses a full Conan reference string and returns a Component.
// ref format: "name/version@user/channel#revision" — all parts after name/version are optional.
func conanRefToComponent(ref, source string) *model.Component {
	m := reConanRef.FindStringSubmatch(strings.TrimSpace(ref))
	if m == nil {
		return nil
	}
	name := m[1]
	version := m[2]
	channel := strings.TrimPrefix(m[3], "@")
	revision := m[4]
	return makeConanComponentFull(name, version, channel, revision, source)
}

// makeConanComponentFull creates a Component with full Conan metadata.
// channel and revision may be empty strings.
func makeConanComponentFull(name, version, channel, revision, source string) *model.Component {
	fp := fingerprints.MatchLibrary(name)
	desc := ""

	// Build PURL per the PURL spec for Conan: channel is a qualifier.
	purl := "pkg:conan/" + name + "@" + version
	if fp != nil {
		purl = fp.PURL + "@" + version
		desc = fp.Description
	}
	if channel != "" && channel != "_/_" && channel != "@_/_" {
		purl += "?channel=" + strings.ReplaceAll(channel, "/", "%2F")
	}

	return &model.Component{
		Name:            name,
		Version:         version,
		PURL:            purl,
		Revision:        revision,
		Channel:         channel,
		DetectionSource: source,
		Description:     desc,
	}
}
