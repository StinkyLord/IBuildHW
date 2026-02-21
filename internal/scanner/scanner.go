// Package scanner orchestrates all detection strategies and merges their results.
package scanner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
	"github.com/StinkyLord/cpp-sbom-builder/internal/strategies"
)

// Strategy is the interface every detection strategy must implement.
type Strategy interface {
	Name() string
	Scan(projectRoot string, verbose bool) ([]*model.Component, error)
}

// Result holds the final merged list of components and metadata about which
// strategies fired.
type Result struct {
	Components        []*model.Component
	DependencyTree    *model.DependencyTree
	StrategiesUsed    []string
	StrategiesSkipped []string
}

// Scanner runs all strategies against a project root and merges the results.
type Scanner struct {
	ProjectRoot string
	Verbose     bool

	// ConanGraph enables the conan-graph strategy active mode.
	// When true the strategy walks the project tree for conanfile.py/txt files
	// and runs `conan graph info <dir> --format=json` for each one (conan must
	// be on PATH — it is pre-installed in the cpp-sbom-builder Docker image).
	// In passive mode (false) the strategy still parses any graph.json files
	// found anywhere in the project tree.
	ConanGraph bool

	// CMakeConfigure enables the cmake-configure strategy.
	// When true the strategy runs cmake configure-only to generate
	// compile_commands.json and link.txt files (MAP equivalent).
	CMakeConfigure bool

	// UseLdd enables the ldd strategy.
	// When true the strategy reads ldd-results.json (produced by the Docker
	// entrypoint) to extract runtime dependency edges from .so files.
	UseLdd bool
}

// New creates a Scanner.
func New(projectRoot string, verbose bool) *Scanner {
	return &Scanner{
		ProjectRoot: projectRoot,
		Verbose:     verbose,
	}
}

// Scan runs all strategies concurrently and returns merged, deduplicated results
// with a full dependency hierarchy (direct vs. transitive).
func (s *Scanner) Scan() (*Result, error) {
	type stratResult struct {
		name       string
		components []*model.Component
		err        error
	}

	// --- Strategies that return graph edges run separately ---

	// ConanGraphStrategy: runs first if --conan-graph is set or a graph.json exists.
	// It supersedes the plain ConanStrategy when it produces results.
	conanGraphStrat := &strategies.ConanGraphStrategy{
		RunConan: s.ConanGraph,
	}
	conanGraphFullResult := conanGraphStrat.ScanWithGraph(s.ProjectRoot, s.Verbose)

	// Plain ConanStrategy (conanfile.txt/py + conan.lock) — used as fallback
	// when conan-graph produced no results.
	conanStrat := &strategies.ConanStrategy{}
	conanLockResult := conanStrat.ScanWithGraph(s.ProjectRoot, s.Verbose)

	// Decide which conan result to use for the dependency graph.
	// conan-graph wins if it found any components (it has richer data).
	var activeConanResult *strategies.ConanScanResult
	var activeConanName string
	if len(conanGraphFullResult.Components) > 0 {
		activeConanResult = conanGraphFullResult
		activeConanName = conanGraphStrat.Name()
	} else {
		activeConanResult = conanLockResult
		activeConanName = conanStrat.Name()
	}

	linkerMapStrat := &strategies.LinkerMapStrategy{}
	linkerMapResult := linkerMapStrat.ScanWithEdges(s.ProjectRoot, s.Verbose)

	binaryEdgesStrat := &strategies.BinaryEdgesStrategy{}
	binaryEdgesResult := binaryEdgesStrat.ScanWithEdges(s.ProjectRoot, s.Verbose)

	// All other strategies (simple component lists, no graph edges)
	otherStrategies := []Strategy{
		&strategies.CompileCommandsStrategy{},
		&strategies.BuildLogsStrategy{},
		&strategies.CMakeStrategy{},
		&strategies.VcpkgStrategy{},
		&strategies.MesonStrategy{},
		&strategies.HeadersStrategy{},
	}

	// Optional strategies activated by flags
	if s.CMakeConfigure {
		otherStrategies = append(otherStrategies, &strategies.CMakeConfigureStrategy{})
	}

	// Channel capacity: base strategies + 3 edge strategies + optional ldd
	capacity := len(otherStrategies) + 3
	if s.UseLdd {
		capacity++
	}
	resultCh := make(chan stratResult, capacity)
	var wg sync.WaitGroup

	// Submit active conan results
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultCh <- stratResult{
			name:       activeConanName,
			components: activeConanResult.Components,
		}
	}()

	// Submit linker map results
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultCh <- stratResult{
			name:       linkerMapStrat.Name(),
			components: linkerMapResult.Components,
		}
	}()

	// Submit binary edges results
	wg.Add(1)
	go func() {
		defer wg.Done()
		resultCh <- stratResult{
			name:       binaryEdgesStrat.Name(),
			components: binaryEdgesResult.Components,
		}
	}()

	// Submit all other strategies
	for _, strat := range otherStrategies {
		wg.Add(1)
		go func(st Strategy) {
			defer wg.Done()
			if s.Verbose {
				fmt.Printf("[scanner] Running strategy: %s\n", st.Name())
			}
			comps, err := st.Scan(s.ProjectRoot, s.Verbose)
			resultCh <- stratResult{name: st.Name(), components: comps, err: err}
		}(strat)
	}

	// LDD strategy: run synchronously here so we can also capture edges,
	// then submit the components to the channel before closing it.
	var lddEdges map[string][]string
	if s.UseLdd {
		lddStrat := &strategies.LddStrategy{}
		lddResult := lddStrat.ScanWithEdges(s.ProjectRoot, s.Verbose)
		lddEdges = lddResult.Edges
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultCh <- stratResult{
				name:       lddStrat.Name(),
				components: lddResult.Components,
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results into a merged map
	// Key: component name (lower) -> best component
	merged := map[string]*model.Component{}
	var used, skipped []string

	for r := range resultCh {
		if r.err != nil {
			if s.Verbose {
				fmt.Printf("[scanner] Strategy %s error: %v\n", r.name, r.err)
			}
			skipped = append(skipped, r.name)
			continue
		}
		if len(r.components) == 0 {
			skipped = append(skipped, r.name)
			continue
		}
		used = append(used, r.name)
		for _, c := range r.components {
			mergeComponent(merged, c)
		}
	}

	// Post-processing: attempt version hints from header files
	allComponents := make([]*model.Component, 0, len(merged))
	for _, c := range merged {
		allComponents = append(allComponents, c)
	}
	strategies.ScanVersionHints(allComponents, s.ProjectRoot)

	// ---- Build Dependency Hierarchy ----
	//
	// Step 1: Mark components as Direct or Transitive.
	//
	// A component is DIRECT if:
	//   a) It appears in conanfile.txt/py DirectNames (explicitly declared by the project), OR
	//   b) It was detected by a compiler/linker artifact strategy (compile_commands, build-logs,
	//      linker-map) — meaning the project's own build system references it directly, OR
	//   c) It was found in vcpkg.json, CMakeLists find_package, or meson dependency() —
	//      all of which are explicit project-level declarations.
	//
	// A component is TRANSITIVE if it only appears in the conan.lock full graph
	// but NOT in the project's own manifest files.

	// Collect all "direct" names from all manifest strategies
	allDirectNames := map[string]bool{}

	// From Conan manifests (conanfile.txt/py) or conan-graph DirectNames
	for name := range activeConanResult.DirectNames {
		allDirectNames[normalizeName(name)] = true
	}

	// From vcpkg.json — run a quick vcpkg scan to get direct names
	vcpkgStrat := &strategies.VcpkgStrategy{}
	vcpkgComps, _ := vcpkgStrat.Scan(s.ProjectRoot, false)
	for _, c := range vcpkgComps {
		allDirectNames[normalizeName(c.Name)] = true
	}

	// From CMake find_package / FetchContent — these are direct
	cmakeStrat := &strategies.CMakeStrategy{}
	cmakeComps, _ := cmakeStrat.Scan(s.ProjectRoot, false)
	for _, c := range cmakeComps {
		allDirectNames[normalizeName(c.Name)] = true
	}

	// From compile_commands.json — external -I paths are direct (the project's build uses them)
	ccStrat := &strategies.CompileCommandsStrategy{}
	ccComps, _ := ccStrat.Scan(s.ProjectRoot, false)
	for _, c := range ccComps {
		allDirectNames[normalizeName(c.Name)] = true
	}

	// From build logs (link.txt, .tlog, ninja) — direct linker references
	blStrat := &strategies.BuildLogsStrategy{}
	blComps, _ := blStrat.Scan(s.ProjectRoot, false)
	for _, c := range blComps {
		allDirectNames[normalizeName(c.Name)] = true
	}

	// From header scan — the project's own source files include these
	hStrat := &strategies.HeadersStrategy{}
	hComps, _ := hStrat.Scan(s.ProjectRoot, false)
	for _, c := range hComps {
		allDirectNames[normalizeName(c.Name)] = true
	}

	// Merge all edge sources into a single map: normalizedName -> []childName
	allEdges := map[string][]string{}
	mergeEdges := func(src map[string][]string) {
		for parent, children := range src {
			pk := normalizeName(parent)
			for _, child := range children {
				allEdges[pk] = appendUniqueStr(allEdges[pk], child)
			}
		}
	}
	mergeEdges(activeConanResult.Edges)
	mergeEdges(linkerMapResult.Edges)
	mergeEdges(binaryEdgesResult.Edges)
	if lddEdges != nil {
		mergeEdges(lddEdges)
	}

	// Step 2: Apply IsDirect and Dependencies to each merged component
	for _, c := range allComponents {
		key := normalizeName(c.Name)
		c.IsDirect = allDirectNames[key]

		// Populate children from all edge sources
		if children, ok := allEdges[key]; ok {
			for _, child := range children {
				c.Dependencies = appendUniqueStr(c.Dependencies, child)
			}
		}
	}

	// Step 3: Build the DependencyTree
	tree := model.BuildDependencyTree(allComponents)

	return &Result{
		Components:        allComponents,
		DependencyTree:    tree,
		StrategiesUsed:    used,
		StrategiesSkipped: skipped,
	}, nil
}

// normalizeName normalises a library name for deduplication:
// lowercases and replaces underscores/hyphens/dots with a canonical separator.
func normalizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}

// mergeComponent merges a newly detected component into the accumulated map.
// Higher-confidence sources (manifest > compiler > header) win on version.
func mergeComponent(merged map[string]*model.Component, incoming *model.Component) {
	key := normalizeName(incoming.Name)
	existing, ok := merged[key]
	if !ok {
		merged[key] = incoming
		return
	}

	// Prefer known version over "unknown"
	if existing.Version == "unknown" && incoming.Version != "unknown" {
		existing.Version = incoming.Version
		existing.PURL = incoming.PURL
	}

	// Prefer higher-confidence detection source
	if sourceRank(incoming.DetectionSource) > sourceRank(existing.DetectionSource) {
		existing.DetectionSource = incoming.DetectionSource
	}

	// Merge include paths
	for _, p := range incoming.IncludePaths {
		existing.IncludePaths = appendUniqueStr(existing.IncludePaths, p)
	}

	// Merge link libraries
	for _, l := range incoming.LinkLibraries {
		existing.LinkLibraries = appendUniqueStr(existing.LinkLibraries, l)
	}

	// Prefer non-empty description
	if existing.Description == "" && incoming.Description != "" {
		existing.Description = incoming.Description
	}
}

// sourceRank returns a priority score for a detection source.
// Higher = more reliable.
func sourceRank(source string) int {
	switch source {
	case "conan-graph":
		return 11
	case "conan", "vcpkg":
		return 10
	case "compile_commands.json":
		return 9
	case "linker-map":
		return 8
	case "build-logs":
		return 7
	case "cmake":
		return 6
	case "meson":
		return 5
	case "header-scan":
		return 1
	default:
		return 0
	}
}

func appendUniqueStr(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
