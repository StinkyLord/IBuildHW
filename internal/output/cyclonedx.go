// Package output provides SBOM serializers.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/StinkyLord/cpp-sbom-builder/internal/model"
	"github.com/StinkyLord/cpp-sbom-builder/internal/scanner"
)

// ---- CycloneDX 1.4 JSON schema types ----

type cdxBOM struct {
	BOMFormat       string              `json:"bomFormat"`
	SpecVersion     string              `json:"specVersion"`
	Version         int                 `json:"version"`
	SerialNumber    string              `json:"serialNumber"`
	Metadata        cdxMetadata         `json:"metadata"`
	Components      []cdxComponent      `json:"components"`
	Dependencies    []cdxDependency     `json:"dependencies,omitempty"`
	HierarchyLevels []cdxHierarchyLevel `json:"x-hierarchyLevels,omitempty"`
}

type cdxHierarchyLevel struct {
	Level      int      `json:"level"`
	Label      string   `json:"label"` // human-readable: "Direct", "Level 1", etc.
	Components []string `json:"components"`
}

type cdxMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []cdxTool `json:"tools"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type        string        `json:"type"`
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	PURL        string        `json:"purl,omitempty"`
	Description string        `json:"description,omitempty"`
	Properties  []cdxProperty `json:"properties,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// cdxDependency represents one node in the CycloneDX dependency graph.
// "ref" is the PURL of the component; "dependsOn" lists the PURLs of its children.
type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// WriteCycloneDX serialises the scan result as a CycloneDX 1.4 JSON SBOM and
// writes it to the given output path. If outputPath is "-", it writes to stdout.
func WriteCycloneDX(result *scanner.Result, outputPath string, toolVersion string) error {
	bom := buildCycloneDX(result, toolVersion)

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CycloneDX JSON: %w", err)
	}

	if outputPath == "-" {
		_, err = os.Stdout.Write(data)
		if err == nil {
			_, err = os.Stdout.WriteString("\n")
		}
		return err
	}

	return os.WriteFile(outputPath, append(data, '\n'), 0644)
}

func buildCycloneDX(result *scanner.Result, toolVersion string) cdxBOM {
	// Sort components by name for deterministic output
	comps := make([]*model.Component, len(result.Components))
	copy(comps, result.Components)
	sort.Slice(comps, func(i, j int) bool {
		return comps[i].Name < comps[j].Name
	})

	// Build a PURL lookup map for resolving child names to PURLs
	purlByName := map[string]string{}
	for _, c := range comps {
		if c.PURL != "" {
			purlByName[c.Name] = c.PURL
		}
	}

	cdxComps := make([]cdxComponent, 0, len(comps))
	var cdxDeps []cdxDependency

	for _, c := range comps {
		comp := cdxComponent{
			Type:        "library",
			Name:        c.Name,
			Version:     c.Version,
			PURL:        c.PURL,
			Description: c.Description,
		}

		// Add dependency type (direct / transitive)
		comp.Properties = append(comp.Properties, cdxProperty{
			Name:  "sbom:dependencyType",
			Value: c.DependencyType(),
		})

		// Conan-specific: revision and channel
		if c.Revision != "" {
			comp.Properties = append(comp.Properties, cdxProperty{
				Name:  "sbom:conan:revision",
				Value: c.Revision,
			})
		}
		if c.Channel != "" && c.Channel != "_/_" {
			comp.Properties = append(comp.Properties, cdxProperty{
				Name:  "sbom:conan:channel",
				Value: c.Channel,
			})
		}

		// Add detection metadata as CycloneDX properties
		if c.DetectionSource != "" {
			comp.Properties = append(comp.Properties, cdxProperty{
				Name:  "sbom:detectionSource",
				Value: c.DetectionSource,
			})
		}
		for _, ip := range c.IncludePaths {
			comp.Properties = append(comp.Properties, cdxProperty{
				Name:  "sbom:includePath",
				Value: ip,
			})
		}
		for _, ll := range c.LinkLibraries {
			comp.Properties = append(comp.Properties, cdxProperty{
				Name:  "sbom:linkLibrary",
				Value: ll,
			})
		}

		cdxComps = append(cdxComps, comp)

		// Build the dependency graph entry for this component
		if c.PURL != "" {
			dep := cdxDependency{
				Ref:       c.PURL,
				DependsOn: []string{},
			}
			// Resolve child names to PURLs
			for _, childName := range c.Dependencies {
				if childPURL, ok := purlByName[childName]; ok {
					dep.DependsOn = append(dep.DependsOn, childPURL)
				} else {
					// Fall back to a generic PURL if we don't have one
					dep.DependsOn = append(dep.DependsOn, "pkg:generic/"+childName)
				}
			}
			cdxDeps = append(cdxDeps, dep)
		}
	}

	// Sort dependencies by ref for deterministic output
	sort.Slice(cdxDeps, func(i, j int) bool {
		return cdxDeps[i].Ref < cdxDeps[j].Ref
	})

	// Build the x-hierarchyLevels extension from the BFS tree
	var hierarchyLevels []cdxHierarchyLevel
	if result.DependencyTree != nil && len(result.DependencyTree.Levels) > 0 {
		for _, level := range result.DependencyTree.Levels {
			label := levelLabel(level.Depth)
			var levelPURLs []string
			for _, c := range level.Components {
				ref := c.PURL
				if ref == "" {
					ref = "pkg:generic/" + c.Name
				}
				levelPURLs = append(levelPURLs, ref)
			}
			hierarchyLevels = append(hierarchyLevels, cdxHierarchyLevel{
				Level:      level.Depth,
				Label:      label,
				Components: levelPURLs,
			})
		}
	}

	return cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		Version:      1,
		SerialNumber: generateURN(),
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cdxTool{
				{
					Vendor:  "StinkyLord",
					Name:    "cpp-sbom-builder",
					Version: toolVersion,
				},
			},
		},
		Components:      cdxComps,
		Dependencies:    cdxDeps,
		HierarchyLevels: hierarchyLevels,
	}
}

// levelLabel returns a human-readable label for a BFS depth level.
// Level 0 is always "Direct". All deeper levels are described generically
// so the function works correctly for any graph depth.
func levelLabel(depth int) string {
	if depth == 0 {
		return "Direct"
	}
	return fmt.Sprintf("Level %d (transitive)", depth)
}

// generateURN produces a simple URN:UUID using the current time.
// For production use, replace with a proper UUID library.
func generateURN() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		now&0xFFFFFFFF,
		(now>>32)&0xFFFF,
		0x4000|((now>>48)&0x0FFF),
		0x8000|(now&0x3FFF),
		now&0xFFFFFFFFFFFF,
	)
}
