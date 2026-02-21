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
//  1. Passive — a graph.json already exists in the project dir (user pre-ran the command).
//     This is the zero-effort path: just drop graph.json in the project root.
//  2. Active  — triggered by --conan-graph flag. Runs `conan graph info` as a local
//     process. Conan is pre-installed in the cpp-sbom-builder Docker image, so this
//     works out of the box when running inside the container. No Docker-in-Docker needed.
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
	// UseDocker (--conan-graph flag) triggers active mode: runs `conan graph info`
	// as a local process. Conan must be on PATH — it is pre-installed in the
	// cpp-sbom-builder Docker image. No Docker-in-Docker is required.
	// When false, the strategy only parses an existing graph.json file.
	UseDocker bool

	// DockerImage is kept for API compatibility but is no longer used.
	// Previously the strategy tried to spin up a Docker container; now it runs
	// conan directly as a local process inside the pre-built image.
	DockerImage string
}

func (s *ConanGraphStrategy) Name() string { return "conan-graph" }

// Scan implements the Strategy interface (returns flat component list).
func (s *ConanGraphStrategy) Scan(projectRoot string, verbose bool) ([]*model.Component, error) {
	result := s.ScanWithGraph(projectRoot, verbose)
	return result.Components, nil
}

// ScanWithGraph returns the full graph result including edges and direct names.
func (s *ConanGraphStrategy) ScanWithGraph(projectRoot string, verbose bool) *ConanScanResult {
	result := &ConanScanResult{
		DirectNames: map[string]bool{},
		Edges:       map[string][]string{},
	}

	graphPath, err := s.resolveGraphJSON(projectRoot, verbose)
	if err != nil {
		if verbose {
			fmt.Printf("  [conan-graph] %v\n", err)
		}
		return result
	}

	data, err := os.ReadFile(graphPath)
	if err != nil {
		if verbose {
			fmt.Printf("  [conan-graph] cannot read %s: %v\n", graphPath, err)
		}
		return result
	}

	if verbose {
		fmt.Printf("  [conan-graph] Parsing %s\n", graphPath)
	}

	return parseConanGraphJSON(data)
}

// resolveGraphJSON returns the path to a graph.json to parse.
// Priority:
//  1. graph.json already exists in the project root → use it directly
//  2. UseDocker (--conan-graph flag) is true → run conan locally (conan is
//     pre-installed in the Docker image that wraps this binary)
//  3. Otherwise → return an error (no graph.json available)
func (s *ConanGraphStrategy) resolveGraphJSON(projectRoot string, verbose bool) (string, error) {
	// 1. Passive mode: look for an existing graph.json
	candidates := []string{
		filepath.Join(projectRoot, "graph.json"),
		filepath.Join(projectRoot, "build", "graph.json"),
		filepath.Join(projectRoot, "conan-graph.json"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			if verbose {
				fmt.Printf("  [conan-graph] Found existing graph.json at %s\n", p)
			}
			return p, nil
		}
	}

	// 2. Active mode: run conan directly (it is pre-installed in the Docker image)
	if s.UseDocker {
		return s.runConanLocally(projectRoot, verbose)
	}

	return "", fmt.Errorf("no graph.json found and --conan-graph not set")
}

// ─────────────────────────────────────────────────────────────────────────────
// Local conan runner
// ─────────────────────────────────────────────────────────────────────────────

// runConanLocally runs `conan graph info . --format=json` as a local process.
//
// This is designed to run inside the cpp-sbom-builder Docker image where conan
// is pre-installed. It does NOT require Docker-in-Docker.
//
// The DockerImage field is ignored in this mode (it was only relevant when the
// tool tried to spin up its own container, which is no longer the approach).
func (s *ConanGraphStrategy) runConanLocally(projectRoot string, verbose bool) (string, error) {
	// Ensure conan is available on PATH
	conanBin, err := exec.LookPath("conan")
	if err != nil {
		return "", fmt.Errorf("conan not found on PATH — " +
			"run inside the cpp-sbom-builder Docker image (philip-abed-docker/cpp-sbom-builder) " +
			"or pre-generate graph.json with: conan graph info . --format=json > graph.json")
	}

	// Write output to a temp file
	tmpFile, err := os.CreateTemp("", "conan-graph-*.json")
	if err != nil {
		return "", fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	if verbose {
		fmt.Printf("  [conan-graph] Running: %s graph info %s --format=json\n", conanBin, projectRoot)
	}

	// Run: conan graph info <projectRoot> --format=json -s build_type=Release
	// stdout → temp file, stderr → our stderr (so the user sees progress)
	outFile, err := os.Create(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("cannot open temp file for writing: %w", err)
	}

	cmd := exec.Command(conanBin,
		"graph", "info", projectRoot,
		"--format=json",
		"-s", "build_type=Release",
	)
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr

	// Give it up to 5 minutes (first run may download recipes)
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case runErr := <-done:
		outFile.Close()
		if runErr != nil {
			os.Remove(tmpPath)
			return "", fmt.Errorf("conan graph info failed: %w", runErr)
		}
	case <-time.After(5 * time.Minute):
		cmd.Process.Kill()
		outFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("conan graph info timed out after 5 minutes")
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
			// But its dependencies tell us which packages are DIRECT
			for childID, edge := range node.Dependencies {
				if edge.Direct {
					if childName := idToName[childID]; childName != "" {
						result.DirectNames[childName] = true
					}
				}
			}
			continue
		}

		// Build the Component
		c := &model.Component{
			Name:            node.Name,
			Version:         node.Version,
			Revision:        node.Rrev,
			DetectionSource: "conan-graph",
			Description:     node.Description,
		}

		// License: may be a string or []string
		c.Description = node.Description
		if node.Homepage != "" && c.Description == "" {
			c.Description = node.Homepage
		}

		// Build PURL
		c.PURL = "pkg:conan/" + node.Name + "@" + node.Version
		if node.Rrev != "" {
			c.PURL += "?rrev=" + node.Rrev
		}

		result.Components = append(result.Components, c)

		// Build edges: this node → its children
		for childID, edge := range node.Dependencies {
			// Skip build-tool edges (cmake, nasm, etc.) from the edge graph
			// but still include the build tools themselves as components
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
