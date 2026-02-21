// Package strategies — ConanGraphStrategy
//
// Parses the rich JSON produced by:
//
//	conan graph info . --format=json
//
// This gives us the full, authoritative dependency tree with:
//   - Exact versions (resolved, not range-based)
//   - Direct vs. transitive classification per edge
//   - License, description, homepage metadata
//   - Build-tool vs. runtime classification
//
// The strategy operates in two modes:
//  1. Passive — walks the project tree and parses any graph.json files found.
//     Zero-effort path: just drop graph.json anywhere in the project.
//  2. Active  — triggered by --conan-graph flag. Walks the project tree to find
//     every conanfile.py / conanfile.txt (at any depth), then runs
//     `conan graph info <dir> --format=json` for each one.
//     Conan is pre-installed in the cpp-sbom-builder Docker image.
//     No Docker-in-Docker needed.
package strategies

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
)

// ─────────────────────────────────────────────────────────────────────────────
// JSON structures for `conan graph info . --format=json`
// ─────────────────────────────────────────────────────────────────────────────

type conanGraphJSON struct {
	Graph struct {
		Nodes map[string]conanGraphNode `json:"nodes"`
	} `json:"graph"`
}

type conanGraphNode struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Ref         string `json:"ref"` // "name/version#rrev"
	Recipe      string `json:"recipe"`
	Context     string `json:"context"` // "host" | "build"
	PackageType string `json:"package_type"`
	License     any    `json:"license"` // string or []string
	Description string `json:"description"`
	Homepage    string `json:"homepage"`
	URL         string `json:"url"`
	Rrev        string `json:"rrev"` // recipe revision hash

	// Per-node dependency edges: map of child node ID → edge metadata
	Dependencies map[string]conanGraphEdge `json:"dependencies"`
}

type conanGraphEdge struct {
	Ref    string `json:"ref"`
	Direct bool   `json:"direct"`
	Build  bool   `json:"build"`
	Skip   bool   `json:"skip"`
	Libs   bool   `json:"libs"`
}

// ─────────────────────────────────────────────────────────────────────────────
// ConanGraphStrategy
// ─────────────────────────────────────────────────────────────────────────────

// ConanGraphStrategy parses the output of `conan graph info . --format=json`.
// It produces a fully resolved dependency tree with direct/transitive edges,
// license metadata, and build-tool classification.
type ConanGraphStrategy struct {
	// RunConan triggers active mode: walks the project tree to find every
	// conanfile.py / conanfile.txt (at any depth) and runs
	// `conan graph info <dir> --format=json` for each one.
	// Conan must be on PATH — it is pre-installed in the cpp-sbom-builder
	// Docker image. No Docker-in-Docker is required.
	// When false, the strategy only parses pre-existing graph.json files.
	RunConan bool
}

func (s *ConanGraphStrategy) Name() string { return "conan-graph" }

// Scan implements the Strategy interface (returns flat component list).
func (s *ConanGraphStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	result := s.ScanWithGraph(projectRoot, verbose)
	return result.Components, nil
}

// ScanWithGraph returns the full graph result including edges and direct names.
// It merges results from all conanfiles found anywhere in the project tree.
func (s *ConanGraphStrategy) ScanWithGraph(projectRoot string, verbose bool) *ConanScanResult {
	merged := &ConanScanResult{
		DirectNames: map[string]bool{},
		Edges:       map[string][]string{},
	}

	// Step 1: collect all pre-existing graph.json files in the tree (passive)
	graphFiles := s.findExistingGraphJSONs(projectRoot, verbose)

	// Step 2: if RunConan is set, find all conanfile dirs and run conan graph info
	if s.RunConan {
		conanDirs := s.findConanfileDirs(projectRoot, verbose)
		for _, dir := range conanDirs {
			path, err := s.runConanLocally(dir, verbose)
			if err != nil {
				if verbose {
					fmt.Printf("  [conan-graph] conan failed in %s: %v\n", dir, err)
				}
				continue
			}
			// avoid duplicates
			found := false
			for _, gf := range graphFiles {
				if gf == path {
					found = true
					break
				}
			}
			if !found {
				graphFiles = append(graphFiles, path)
			}
		}
	}

	if len(graphFiles) == 0 {
		if verbose {
			fmt.Println("  [conan-graph] No graph.json files found and --conan-graph not set")
		}
		return merged
	}

	// Step 3: parse and merge all graph.json files
	for _, gf := range graphFiles {
		data, err := os.ReadFile(gf)
		if err != nil {
			if verbose {
				fmt.Printf("  [conan-graph] cannot read %s: %v\n", gf, err)
			}
			continue
		}
		if verbose {
			fmt.Printf("  [conan-graph] Parsing %s\n", gf)
		}
		r := parseConanGraphJSON(data)
		merged.Components = append(merged.Components, r.Components...)
		for k, v := range r.DirectNames {
			merged.DirectNames[k] = v
		}
		for parent, children := range r.Edges {
			for _, child := range children {
				merged.Edges[parent] = appendUnique(merged.Edges[parent], child)
			}
		}
	}

	return merged
}

// findExistingGraphJSONs walks the project tree and returns all graph.json /
// conan-graph.json files found (passive mode — no conan invocation).
func (s *ConanGraphStrategy) findExistingGraphJSONs(projectRoot string, verbose bool) []string {
	var found []string
	_ = filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".conan" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if name == "graph.json" || name == "conan-graph.json" {
			if verbose {
				fmt.Printf("  [conan-graph] Found existing graph.json: %s\n", path)
			}
			found = append(found, path)
		}
		return nil
	})
	return found
}

// findConanfileDirs walks the project tree and returns the directory of every
// conanfile.py or conanfile.txt found (at any depth).
// Each directory is returned only once even if both files exist in it.
func (s *ConanGraphStrategy) findConanfileDirs(projectRoot string, verbose bool) []string {
	seen := map[string]bool{}
	var dirs []string

	_ = filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".conan" ||
				name == "build" || name == "_build" || name == "cmake-build" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if name == "conanfile.py" || name == "conanfile.txt" {
			dir := filepath.Dir(path)
			if !seen[dir] {
				seen[dir] = true
				dirs = append(dirs, dir)
				if verbose {
					fmt.Printf("  [conan-graph] Found conanfile in: %s\n", dir)
				}
			}
		}
		return nil
	})
	return dirs
}

// ─────────────────────────────────────────────────────────────────────────────
// Local conan runner
// ─────────────────────────────────────────────────────────────────────────────

// runConanLocally runs `conan graph info <conanfileDir> --format=json` as a
// local process. Conan must be on PATH — it is pre-installed in the
// cpp-sbom-builder Docker image. No Docker-in-Docker is required.
func (s *ConanGraphStrategy) runConanLocally(conanfileDir string, verbose bool) (string, error) {
	conanBin, err := exec.LookPath("conan")
	if err != nil {
		return "", fmt.Errorf("conan not found on PATH — " +
			"run inside the cpp-sbom-builder Docker image (philip-abed-docker/cpp-sbom-builder) " +
			"or pre-generate graph.json with: conan graph info . --format=json > graph.json")
	}

	tmpFile, err := os.CreateTemp("", "conan-graph-*.json")
	if err != nil {
		return "", fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	if verbose {
		fmt.Printf("  [conan-graph] Running: %s graph info %s --format=json\n", conanBin, conanfileDir)
	}

	outFile, err := os.Create(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("cannot open temp file for writing: %w", err)
	}

	cmd := exec.Command(conanBin,
		"graph", "info", conanfileDir,
		"--format=json",
		"-s", "build_type=Release",
	)
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case runErr := <-done:
		outFile.Close()
		if runErr != nil {
			os.Remove(tmpPath)
			return "", fmt.Errorf("conan graph info failed in %s: %w", conanfileDir, runErr)
		}
	case <-time.After(5 * time.Minute):
		cmd.Process.Kill()
		outFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("conan graph info timed out after 5 minutes (dir: %s)", conanfileDir)
	}

	if verbose {
		fmt.Printf("  [conan-graph] graph.json written to %s\n", tmpPath)
	}
	return tmpPath, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────────────────────────────────────

// parseConanGraphJSON parses the JSON produced by `conan graph info . --format=json`
// and returns a ConanScanResult with full graph edges and direct/transitive info.
func parseConanGraphJSON(data []byte) *ConanScanResult {
	result := &ConanScanResult{
		DirectNames: map[string]bool{},
		Edges:       map[string][]string{},
	}

	var g conanGraphJSON
	if err := json.Unmarshal(data, &g); err != nil {
		return result
	}

	nodes := g.Graph.Nodes

	// Build a map: node ID → package name (for edge resolution)
	idToName := map[string]string{}
	for id, node := range nodes {
		if node.Name != "" {
			idToName[id] = node.Name
		}
	}

	// Process each node
	for id, node := range nodes {
		// Node "0" is the project root (Consumer) — not a real package
		if id == "0" || node.Name == "" {
			// Its dependencies tell us which packages are DIRECT
			for childID, edge := range node.Dependencies {
				if edge.Direct {
					if childName := idToName[childID]; childName != "" {
						result.DirectNames[childName] = true
					}
				}
			}
			continue
		}

		c := &model.Component{
			Name:            node.Name,
			Version:         node.Version,
			Revision:        node.Rrev,
			DetectionSource: "conan-graph",
			Description:     node.Description,
		}

		if node.Homepage != "" && c.Description == "" {
			c.Description = node.Homepage
		}

		c.PURL = "pkg:conan/" + node.Name + "@" + node.Version
		if node.Rrev != "" {
			c.PURL += "?rrev=" + node.Rrev
		}

		result.Components = append(result.Components, c)

		// Build edges: this node → its children (skip build-tool edges)
		for childID, edge := range node.Dependencies {
			if edge.Build {
				continue
			}
			if childName := idToName[childID]; childName != "" && childName != node.Name {
				result.Edges[node.Name] = appendUnique(result.Edges[node.Name], childName)
			}
		}
	}

	return result
}
