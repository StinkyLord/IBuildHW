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
// The strategy can operate in two modes:
//  1. Passive  — a graph.json already exists in the project dir (user pre-ran the command)
//  2. Active   — the tool runs conan inside a Docker container and captures the output
//
// Active mode is triggered by the --conan-graph flag and requires Docker on the host.
// It never installs anything on the customer's machine.
package strategies

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	// UseDocker controls whether to run conan inside a Docker container.
	// When false the strategy only parses an existing graph.json file.
	UseDocker bool

	// DockerImage is the Docker image that has conan pre-installed.
	// Defaults to "conanio/conan:latest".
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
//  2. UseDocker is true → run conan inside Docker, capture output to a temp file
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

	// 2. Active mode: run conan inside Docker
	if s.UseDocker {
		return s.runConanInDocker(projectRoot, verbose)
	}

	return "", fmt.Errorf("no graph.json found and --conan-graph not set")
}

// ─────────────────────────────────────────────────────────────────────────────
// Docker runner
// ─────────────────────────────────────────────────────────────────────────────

const defaultDockerImage = "conanio/conan:latest"

// runConanInDocker runs `conan graph info . --format=json` inside a Docker
// container that has Conan pre-installed. The project directory is mounted
// read-only; the output is written to a temp file on the host.
//
// Nothing is installed on the customer's machine — Docker must already be
// available (it is a standard developer tool).
func (s *ConanGraphStrategy) runConanInDocker(projectRoot string, verbose bool) (string, error) {
	image := s.DockerImage
	if image == "" {
		image = defaultDockerImage
	}

	// Ensure Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker not found on PATH — install Docker or pre-generate graph.json manually")
	}

	// Create a temp file to receive the JSON output
	tmpFile, err := os.CreateTemp("", "conan-graph-*.json")
	if err != nil {
		return "", fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpFile.Close()
	tmpPath := tmpFile.Name()

	// Normalise the project root path for Docker volume mounting.
	// On Windows, convert C:\path\to\dir → /c/path/to/dir (Git-bash / Docker Desktop style)
	mountSrc := toDockerPath(projectRoot)

	// The container writes graph.json to /output/graph.json which is mapped to
	// a host temp directory.
	tmpDir := filepath.Dir(tmpPath)
	outputMount := toDockerPath(tmpDir)

	// Build the docker run command:
	//   docker run --rm
	//     -v <projectRoot>:/project:ro
	//     -v <tmpDir>:/output
	//     -w /project
	//     <image>
	//     bash -c "conan graph info . --format=json > /output/graph.json"
	args := []string{
		"run", "--rm",
		"-v", mountSrc + ":/project:ro",
		"-v", outputMount + ":/output",
		"-w", "/project",
		image,
		"bash", "-c",
		"conan graph info . --format=json > /output/" + filepath.Base(tmpPath),
	}

	if verbose {
		fmt.Printf("  [conan-graph] Running: docker %s\n", strings.Join(args, " "))
	}

	cmd := exec.Command("docker", args...)
	cmd.Stdout = os.Stderr // progress to stderr
	cmd.Stderr = os.Stderr

	// Give it up to 5 minutes (first run pulls the image)
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			os.Remove(tmpPath)
			return "", fmt.Errorf("docker conan graph info failed: %w", err)
		}
	case <-time.After(5 * time.Minute):
		cmd.Process.Kill()
		os.Remove(tmpPath)
		return "", fmt.Errorf("docker conan graph info timed out after 5 minutes")
	}

	if verbose {
		fmt.Printf("  [conan-graph] graph.json written to %s\n", tmpPath)
	}
	return tmpPath, nil
}

// toDockerPath converts a host path to a Docker-compatible mount path.
// On Windows: C:\Users\foo → /c/Users/foo
// On Linux/Mac: unchanged.
func toDockerPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	// Replace backslashes with forward slashes
	p = filepath.ToSlash(p)
	// Convert drive letter: C:/... → /c/...
	if len(p) >= 2 && p[1] == ':' {
		drive := strings.ToLower(string(p[0]))
		p = "/" + drive + p[2:]
	}
	return p
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
